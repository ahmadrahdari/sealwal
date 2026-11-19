import os
import struct
import threading
import zlib

import pytest

from sealwal import GroupCommitter, SealedLog, check_proof, make_signer, prove, verify
from sealwal import format as fmt
from sealwal.log import CorruptLogError
from sealwal.verify import scan

ALGS = ["none", "ed25519", "ml-dsa-44", "ml-dsa-65"]


def write_log(path, signer, batches=(3, 1, 5, 2), **kw):
    log = SealedLog.create(path, signer, sync="none", **kw)
    lsn = 0
    for n in batches:
        for _ in range(n):
            lsn += 1
            log.append(f"record-{lsn}".encode())
        log.commit()
    return log


def frames(path):
    return scan(path).frames


def rewrite_frame(path, index, new_body):
    """Replace one frame's body and fix up its CRC, as an attacker would."""
    with open(path, "rb") as f:
        buf = bytearray(f.read())
    off, ftype, _body, end = frames(path)[index]
    head = struct.pack(">BI", ftype, len(new_body))
    new = head + new_body + struct.pack(">I", zlib.crc32(head + new_body))
    buf[off:end] = new
    with open(path, "wb") as f:
        f.write(buf)


def delete_frames(path, start, stop):
    with open(path, "rb") as f:
        buf = bytearray(f.read())
    fr = frames(path)
    a, b = fr[start][0], fr[stop - 1][3]
    del buf[a:b]
    with open(path, "wb") as f:
        f.write(buf)


@pytest.mark.parametrize("alg", ALGS)
def test_roundtrip_verifies(tmp_path, alg):
    s = make_signer(alg)
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    rep = verify(p, s.public_bytes if alg != "none" else None)
    assert rep.ok, rep.errors
    assert rep.seals == 4 and rep.committed_lsn == 11
    if alg != "none":
        assert rep.authenticated_lsn == 11 and rep.unauthenticated_seals == 0


@pytest.mark.parametrize("alg", ["none", "ml-dsa-44"])
def test_modified_record_is_detected(tmp_path, alg):
    s = make_signer(alg)
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    rewrite_frame(p, 1, struct.pack(">Q", 2) + b"record-X")  # LSN 2, new payload, valid CRC
    rep = verify(p, s.public_bytes if alg != "none" else None)
    assert not rep.ok and "Merkle root mismatch" in rep.errors[0]


def test_attacker_who_reseals_without_key_is_caught(tmp_path):
    """Modify a record AND recompute every Merkle root / digest. Without the
    key the signatures no longer verify."""
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s, batches=(2,)).close()
    rewrite_frame(p, 0, struct.pack(">Q", 1) + b"evil")
    from sealwal import merkle

    hdr = scan(p).header
    root = merkle.root([merkle.leaf_hash(1, b"evil"), merkle.leaf_hash(2, b"record-2")])
    sealbody = fmt.parse_seal(frames(p)[2][2])
    forged = fmt.SealRecord(0, 1, 2, root, hdr.genesis_digest(), sealbody.signature)
    rewrite_frame(p, 2, fmt.encode_seal(forged)[5:-4])
    rep = verify(p, s.public_bytes)
    assert not rep.ok and "invalid signature" in rep.errors[0]


def test_swapped_header_key_is_caught_when_key_is_pinned(tmp_path):
    good, evil = make_signer("ed25519"), make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, evil).close()  # attacker builds a whole consistent log with their own key
    assert verify(p, trust_header_key=True).ok  # looks fine if you trust the header...
    rep = verify(p, good.public_bytes)  # ...but not against the pinned key
    assert not rep.ok and "does not match the pinned key" in rep.errors[0]


def test_deleted_batch_is_detected(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    # batch 2 = frames 4 (DATA) and 5 (SEAL)
    delete_frames(p, 4, 6)
    rep = verify(p, s.public_bytes)
    assert not rep.ok


def test_reordered_records_are_detected(tmp_path):
    s = make_signer("none")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    a, b = frames(p)[0][2], frames(p)[1][2]
    rewrite_frame(p, 0, b)
    rewrite_frame(p, 1, a)
    rep = verify(p)
    assert not rep.ok and "expected LSN" in rep.errors[0]


def test_rollback_needs_an_anchor(tmp_path):
    s = make_signer("ml-dsa-44")
    p = tmp_path / "a.wal"
    log = write_log(p, s)
    anchor = log.anchor()
    log.close()
    # attacker cuts the last batch off (DATA, DATA, SEAL, plus the close-time SIG if any)
    fr = frames(p)
    seal_idx = [i for i, f in enumerate(fr) if f[1] == fmt.SEAL]
    with open(p, "r+b") as f:
        f.truncate(fr[seal_idx[-2]][3])
    assert verify(p, s.public_bytes).ok  # a shorter log is still a valid log
    rep = verify(p, s.public_bytes, anchor=anchor)
    assert not rep.ok and "rollback" in rep.errors[0]


def test_corruption_in_the_middle_is_not_a_torn_tail(tmp_path):
    s = make_signer("none")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    off = frames(p)[2][0]
    with open(p, "r+b") as f:
        f.seek(off + 12)
        f.write(b"\xff")
    rep = verify(p)
    assert not rep.ok and "middle of the log" in rep.errors[-1]


def test_torn_tail_is_recovered(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    size = os.path.getsize(p)
    with open(p, "ab") as f:  # half-written next batch
        f.write(fmt.encode_data(12, b"record-12") + fmt.encode_data(13, b"record-13")[:7])
    rep = verify(p, s.public_bytes)
    assert rep.ok and rep.unsealed_records == 1 and rep.torn_bytes == 7
    log = SealedLog.open(p, s, sync="none")
    assert os.path.getsize(p) == size and log.committed_lsn == 11
    assert log.append(b"after-recovery") == 12
    log.close()
    rep = verify(p, s.public_bytes)
    assert rep.ok and rep.committed_lsn == 12 and rep.unauthenticated_seals == 0


@pytest.mark.parametrize("k", [1, 3, 8])
def test_sign_every_k_authentication_window(tmp_path, k):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    log = write_log(p, s, batches=[1] * 10, sign_every=k)
    os.fsync(log._fd)
    rep = verify(p, s.public_bytes)  # before close: tail may be unsigned
    assert rep.ok
    assert rep.unauthenticated_seals == (10 % k if k > 1 else 0)
    log.close()
    rep = verify(p, s.public_bytes)
    assert rep.ok and rep.unauthenticated_seals == 0


def test_async_signing_eventually_covers_everything(tmp_path):
    s = make_signer("ml-dsa-65")
    p = tmp_path / "a.wal"
    log = write_log(p, s, batches=[2] * 50, async_sign=True)
    log.close()
    rep = verify(p, s.public_bytes)
    assert rep.ok, rep.errors
    assert rep.committed_lsn == 100 and rep.unauthenticated_seals == 0


def test_crash_inside_authentication_window_is_resigned_on_open(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    log = write_log(p, s, batches=[1] * 5, sign_every=4)
    os.close(log._fd)  # simulate a crash: seal #4 is committed but unsigned
    assert verify(p, s.public_bytes).unauthenticated_seals == 1
    log2 = SealedLog.open(p, s, sync="none")
    assert log2.recovery_report.unauthenticated_seals == 1
    log2.close()
    assert verify(p, s.public_bytes).unauthenticated_seals == 0


def test_open_refuses_a_tampered_log(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    rewrite_frame(p, 0, struct.pack(">Q", 1) + b"evil")
    with pytest.raises(CorruptLogError):
        SealedLog.open(p, s)


@pytest.mark.parametrize("sign_every", [1, 4])
def test_inclusion_proofs(tmp_path, sign_every):
    s = make_signer("ml-dsa-44")
    p = tmp_path / "a.wal"
    write_log(p, s, batches=[7, 1, 16, 5, 3], sign_every=sign_every).close()
    for lsn in range(1, 33):
        proof = prove(p, lsn)
        ok, why = check_proof(proof, s.public_bytes)
        assert ok, (lsn, why)
    proof = prove(p, 10)
    proof["payload"] = b"forged".hex()
    assert not check_proof(proof, s.public_bytes)[0]
    assert not check_proof(prove(p, 10), make_signer("ml-dsa-44").public_bytes)[0]


def test_group_commit_many_threads(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    log = SealedLog.create(p, s, sync="fdatasync", async_sign=True)
    gc = GroupCommitter(log)
    lsns, lock = [], threading.Lock()

    def client(cid):
        for i in range(50):
            lsn = gc.submit(f"c{cid}-{i}".encode())
            assert log.committed_lsn >= lsn  # durable when submit returns
            with lock:
                lsns.append(lsn)

    ts = [threading.Thread(target=client, args=(c,)) for c in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    gc.close()
    log.close()
    assert sorted(lsns) == list(range(1, 401))
    assert sum(gc.batches) == 400
    rep = verify(p, s.public_bytes)
    assert rep.ok and rep.committed_lsn == 400 and rep.unauthenticated_seals == 0
