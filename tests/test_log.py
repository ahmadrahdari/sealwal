import os
import struct
import threading
import time
import zlib

import pytest

from sealwal import (Erased, GroupCommitter, KeyStore, SealedLog, check_consistency, check_proof,
                     make_signer, prove, prove_consistency, read_records, verify)
from sealwal import format as fmt
from sealwal import merkle
from sealwal.log import CorruptLogError
from sealwal.privacy import ZERO_SALT, commit
from sealwal.verify import scan

ALGS = ["none", "ed25519", "ml-dsa-44", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "lms-hss"]


def write_log(path, signer, batches=(3, 1, 5, 2), **kw):
    log = SealedLog.create(path, signer, sync="none", **kw)
    lsn = 0
    for n in batches:
        for _ in range(n):
            lsn += 1
            log.append(b"record-%d" % lsn)
        log.commit()
    return log


def frames(path):
    return scan(path).frames


def rewrite_frame(path, i, body):
    # what an attacker with write access does: new body, fixed-up CRC
    with open(path, "rb") as f:
        buf = bytearray(f.read())
    off, ftype, _, end = frames(path)[i]
    head = struct.pack(">BI", ftype, len(body))
    buf[off:end] = head + body + struct.pack(">I", zlib.crc32(head + body))
    with open(path, "wb") as f:
        f.write(buf)


def cut_frames(path, start, stop):
    with open(path, "rb") as f:
        buf = bytearray(f.read())
    fr = frames(path)
    del buf[fr[start][0]:fr[stop - 1][3]]
    with open(path, "wb") as f:
        f.write(buf)


def public(lsn, payload, c=None):
    c = commit(ZERO_SALT, payload) if c is None else c
    return fmt.data_body(lsn, 0, c, payload)


def pub(s):
    return s.public_bytes if s.alg != "none" else None


@pytest.mark.parametrize("alg", ALGS)
def test_roundtrip(tmp_path, alg):
    s = make_signer(alg)
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    rep = verify(p, pub(s))
    assert rep.ok, rep.errors
    assert rep.seals == 4 and rep.committed_lsn == 11
    if alg != "none":
        assert rep.authenticated_lsn == 11 and rep.unauthenticated_seals == 0


@pytest.mark.parametrize("alg", ["none", "ml-dsa-44"])
def test_modified_record(tmp_path, alg):
    s = make_signer(alg)
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    c_old = fmt.parse_data(frames(p)[1][2])[2]
    rewrite_frame(p, 1, public(2, b"record-X", c=c_old))       # payload only
    rep = verify(p, pub(s))
    assert not rep.ok and "commitment" in rep.errors[0]
    rewrite_frame(p, 1, public(2, b"record-X"))                 # payload + commitment
    rep = verify(p, pub(s))
    assert not rep.ok and "Merkle root mismatch" in rep.errors[0]


def test_reseal_without_key(tmp_path):
    # change a record AND recompute the root; the signature gives it away
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s, batches=(2,)).close()
    rewrite_frame(p, 0, public(1, b"evil"))
    root = merkle.root([merkle.leaf_hash(1, commit(ZERO_SALT, b"evil")),
                        merkle.leaf_hash(2, commit(ZERO_SALT, b"record-2"))])
    old = fmt.parse_seal(frames(p)[2][2])
    forged = fmt.SealRecord(0, 1, 2, root, scan(p).header.genesis_digest(), old.signature)
    rewrite_frame(p, 2, fmt.encode_seal(forged)[5:-4])
    rep = verify(p, s.public_bytes)
    assert not rep.ok and "invalid signature" in rep.errors[0]


def test_swapped_key(tmp_path):
    good, evil = make_signer("ed25519"), make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, evil).close()
    assert verify(p, trust_header_key=True).ok
    rep = verify(p, good.public_bytes)
    assert not rep.ok and "pinned key" in rep.errors[0]


def test_dropped_batch(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    cut_frames(p, 4, 6)
    assert not verify(p, s.public_bytes).ok


def test_reordered(tmp_path):
    s = make_signer("none")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    a, b = frames(p)[0][2], frames(p)[1][2]
    rewrite_frame(p, 0, b)
    rewrite_frame(p, 1, a)
    rep = verify(p)
    assert not rep.ok and "expected LSN" in rep.errors[0]


def test_rollback_needs_anchor(tmp_path):
    s = make_signer("ml-dsa-44")
    p = tmp_path / "a.wal"
    log = write_log(p, s)
    anchor = log.anchor()
    log.close()
    seals = [i for i, f in enumerate(frames(p)) if f[1] == fmt.SEAL]
    with open(p, "r+b") as f:
        f.truncate(frames(p)[seals[-2]][3])
    assert verify(p, s.public_bytes).ok          # a shorter log is still a valid log
    rep = verify(p, s.public_bytes, anchor=anchor)
    assert not rep.ok and "rollback" in rep.errors[0]


def test_mid_log_corruption(tmp_path):
    s = make_signer("none")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    with open(p, "r+b") as f:
        f.seek(frames(p)[2][0] + 12)
        f.write(b"\xff")
    rep = verify(p)
    assert not rep.ok and "middle of the log" in rep.errors[-1]


def test_torn_tail(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    size = os.path.getsize(p)
    with open(p, "ab") as f:
        f.write(fmt.encode_data(12, 0, commit(ZERO_SALT, b"r12"), b"r12")
                + fmt.encode_data(13, 0, commit(ZERO_SALT, b"r13"), b"r13")[:7])
    rep = verify(p, s.public_bytes)
    assert rep.ok and rep.unsealed_records == 1 and rep.torn_bytes == 7
    log = SealedLog.open(p, s, sync="none")
    assert os.path.getsize(p) == size and log.committed_lsn == 11
    assert log.append(b"after") == 12
    log.close()
    rep = verify(p, s.public_bytes)
    assert rep.ok and rep.committed_lsn == 12 and rep.unauthenticated_seals == 0


def test_torn_tail_with_junk_after_it(tmp_path):
    # the last frame is cut short and the rest of the sector is garbage, so the
    # broken frame "fits" in the file. Still a torn tail, not tampering.
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    size = os.path.getsize(p)
    frame = fmt.encode_data(12, 0, commit(ZERO_SALT, b"r12"), b"r12" * 20)
    with open(p, "ab") as f:
        f.write(frame[:-6] + b"\x00\x13\x37" * 10)
    log = SealedLog.open(p, s, sync="none")
    assert os.path.getsize(p) == size and log.committed_lsn == 11
    log.close()


def test_damaged_frame_followed_by_good_ones_is_not_a_torn_tail(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    last = frames(p)[-1]
    with open(p, "r+b") as f:
        f.seek(last[0] - 3)          # inside the frame before the last one
        f.write(b"\xaa")
    with pytest.raises(CorruptLogError):
        SealedLog.open(p, s, sync="none")


@pytest.mark.parametrize("k", [1, 3, 8])
def test_sign_every_k(tmp_path, k):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    log = write_log(p, s, batches=[1] * 10, sign_every=k)
    rep = verify(p, s.public_bytes)
    assert rep.ok and rep.unauthenticated_seals == (10 % k if k > 1 else 0)
    log.close()
    assert verify(p, s.public_bytes).unauthenticated_seals == 0


def test_async_signing(tmp_path):
    s = make_signer("ml-dsa-65")
    p = tmp_path / "a.wal"
    write_log(p, s, batches=[2] * 50, async_sign=True).close()
    rep = verify(p, s.public_bytes)
    assert rep.ok and rep.committed_lsn == 100 and rep.unauthenticated_seals == 0


def test_bounded_window(tmp_path):
    s = make_signer("ml-dsa-44")
    for k in (0, 2):
        p = tmp_path / ("k%d.wal" % k)
        log = SealedLog.create(p, s, sync="none", async_sign=True, max_unsigned=k)
        for i in range(40):
            log.append(b"x%d" % i)
            seal = log.commit()
            assert seal.seal_no - log.signed_seal <= k
        log.close()
        assert verify(p, s.public_bytes).ok


def test_crash_in_window_resigns(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    log = write_log(p, s, batches=[1] * 5, sign_every=4)
    os.close(log._fd)                             # crash, seal #4 unsigned
    assert verify(p, s.public_bytes).unauthenticated_seals == 1
    log = SealedLog.open(p, s, sync="none")
    assert log.recovery_report.unauthenticated_seals == 1
    log.close()
    assert verify(p, s.public_bytes).unauthenticated_seals == 0


def test_open_refuses_tampered(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s).close()
    rewrite_frame(p, 0, public(1, b"evil"))
    with pytest.raises(CorruptLogError):
        SealedLog.open(p, s)


@pytest.mark.parametrize("every", [1, 4])
def test_inclusion_proofs(tmp_path, every):
    s = make_signer("ml-dsa-44")
    p = tmp_path / "a.wal"
    write_log(p, s, batches=[7, 1, 16, 5, 3], sign_every=every).close()
    for lsn in range(1, 33):
        ok, why = check_proof(prove(p, lsn), s.public_bytes)
        assert ok, (lsn, why)
    proof = prove(p, 10)
    proof["opening"]["payload"] = b"forged".hex()
    assert not check_proof(proof, s.public_bytes)[0]
    assert not check_proof(prove(p, 10), make_signer("ml-dsa-44").public_bytes)[0]


def test_consistency_between_seals(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    write_log(p, s, batches=[3, 1, 4, 1, 5, 9, 2, 6]).close()
    st = {}
    verify(p, s.public_bytes, _state_out=st)
    for seal in st["seals"]:
        ok, why = check_consistency(prove_consistency(p, seal.seal_no), s.public_bytes, seal.digest)
        assert ok, why


def test_fork_detected(tmp_path):
    # same key, but someone rewrites history after seal #1; an auditor who
    # kept the digest of seal #2 from the real log sees it
    s = make_signer("ed25519")
    a, b = tmp_path / "a.wal", tmp_path / "b.wal"
    write_log(a, s, batches=[2, 2, 2]).close()
    st = {}
    verify(a, s.public_bytes, _state_out=st)
    anchored = st["seals"][2].digest
    log = write_log(b, s, batches=[2, 2])
    log.append(b"different")
    log.append(b"history")
    log.close()
    ok, _ = check_consistency(prove_consistency(b, 2), s.public_bytes, anchored)
    assert not ok


def test_hybrid_needs_both(tmp_path):
    s = make_signer("hybrid-ed25519-ml-dsa-65")
    p = tmp_path / "a.wal"
    write_log(p, s, batches=(2,)).close()
    body = bytearray(frames(p)[2][2])
    body[-1] ^= 1                                 # ML-DSA half
    rewrite_frame(p, 2, bytes(body))
    rep = verify(p, s.public_bytes)
    assert not rep.ok and "invalid signature" in rep.errors[0]


def test_lms_crash_and_restart(tmp_path):
    from sealwal import lms
    kf = tmp_path / "k.json"
    lms.EpochHss(kf, create=True).close()
    s = make_signer("lms-hss", str(kf).encode())
    p = tmp_path / "a.wal"
    log = write_log(p, s, batches=[1] * 20)
    os.close(log._fd)                             # crash
    s2 = make_signer("lms-hss", str(kf).encode())
    assert s2.public_bytes == s.public_bytes
    log = SealedLog.open(p, s2, sync="none")
    log.append(b"after crash")
    log.close()
    rep = verify(p, s.public_bytes)
    assert rep.ok and rep.committed_lsn == 21 and rep.unauthenticated_seals == 0
    assert check_proof(prove(p, 21), s.public_bytes)[0]


def test_lms_epochs_never_repeat(tmp_path):
    from sealwal import lms
    kf = tmp_path / "k.json"
    seen = []
    for _ in range(4):
        k = lms.EpochHss(kf, create=not kf.exists())
        k.close()
        seen += k.epochs_used
    assert len(seen) == len(set(seen))


def test_lms_rollover(tmp_path):
    from sealwal import lms
    k = lms.EpochHss(tmp_path / "k.json", h1=5, create=True)   # 32 sigs per epoch
    sigs = [(b"m%d" % i, k.sign(b"m%d" % i)) for i in range(100)]
    k.close()
    assert len(set(k.epochs_used)) == len(k.epochs_used) >= 4
    assert all(lms.hss_verify(k.public_key, m, sg) for m, sg in sigs)
    assert not lms.hss_verify(k.public_key, b"m0", sigs[1][1])


def test_group_commit(tmp_path):
    s = make_signer("ed25519")
    p = tmp_path / "a.wal"
    log = SealedLog.create(p, s, sync="fdatasync", async_sign=True)
    gc = GroupCommitter(log)
    got, lock = [], threading.Lock()

    def client(c):
        for i in range(50):
            lsn = gc.submit(b"c%d-%d" % (c, i))
            assert log.committed_lsn >= lsn
            with lock:
                got.append(lsn)

    ts = [threading.Thread(target=client, args=(c,)) for c in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    gc.close()
    log.close()
    assert sorted(got) == list(range(1, 401)) and sum(gc.batches) == 400
    rep = verify(p, s.public_bytes)
    assert rep.ok and rep.committed_lsn == 400 and rep.unauthenticated_seals == 0


# --- privacy, erasure, provenance receipts ---------------------------------

def private_log(tmp_path, alg="ed25519"):
    s = make_signer(alg)
    keys = KeyStore(tmp_path / "keys.json", create=True)
    for u in (1, 2, 3):
        keys.add_subject(u)
    p = tmp_path / "p.wal"
    log = SealedLog.create(p, s, sync="none", keys=keys)
    for i in range(30):
        log.append(b'{"user": %d, "balance": %d}' % (i % 3 + 1, 1000 + i), subject=i % 3 + 1)
        if i % 5 == 4:
            log.commit()
    log.append(b"public notice", subject=0)
    log.close()
    return s, keys, p


def test_private_roundtrip(tmp_path):
    s, keys, p = private_log(tmp_path)
    rep = verify(p, s.public_bytes, keys=keys)
    assert rep.ok and rep.private_records == 30 and rep.erased_records == 0 and rep.contents_checked
    got = list(read_records(p, keys))
    assert len(got) == 31 and all(pl is not None for _, _, pl in got)


def test_auditor_needs_no_keys(tmp_path):
    s, keys, p = private_log(tmp_path)
    rep = verify(p, s.public_bytes)                 # no keys
    assert rep.ok and not rep.contents_checked
    st = {}
    verify(p, s.public_bytes, _state_out=st)
    ok, _ = check_consistency(prove_consistency(p, 1), s.public_bytes, st["seals"][1].digest)
    assert ok
    assert all(pl is None for _, subj, pl in read_records(p) if subj)


def test_erasure(tmp_path):
    s, keys, p = private_log(tmp_path)
    keys.shred(2)
    rep = verify(p, s.public_bytes, keys=keys)
    assert rep.ok and rep.erased_records == 10
    for lsn, subj, payload in read_records(p, keys):
        assert (payload is None) == (subj == 2)
    # receipts for other users still work, the erased user's can't be opened
    assert check_proof(prove(p, 1, keys), s.public_bytes)[0]
    with pytest.raises(Erased):
        prove(p, 2, keys)
    # but its position can still be proven, revealing nothing
    ok, why = check_proof(prove(p, 2, keys, reveal=False), s.public_bytes)
    assert ok and "not revealed" in why
    # recovery after erasure is fine
    log = SealedLog.open(p, s, sync="none", keys=keys)
    log.append(b"later", subject=1)
    log.close()
    assert verify(p, s.public_bytes, keys=keys).ok


def test_ciphertext_tamper(tmp_path):
    s, keys, p = private_log(tmp_path)
    data = [i for i, f in enumerate(frames(p)) if f[1] == fmt.DATA]
    lsn, subj, c, body = fmt.parse_data(frames(p)[data[3]][2])
    other = fmt.parse_data(frames(p)[data[0]][2])[3]
    rewrite_frame(p, data[3], fmt.data_body(lsn, subj, c, other))
    assert verify(p, s.public_bytes).ok             # structure is intact...
    rep = verify(p, s.public_bytes, keys=keys)      # ...the data owner sees it
    assert not rep.ok and "modified" in rep.errors[0]


def test_receipt_does_not_leak_neighbours(tmp_path):
    # public records: a neighbour's leaf can be brute-forced from a receipt
    s = make_signer("ed25519")
    p = tmp_path / "pub.wal"
    log = SealedLog.create(p, s, sync="none")
    log.append(b'{"balance": 1234}')
    log.append(b'{"balance": 777}')
    log.close()
    sibling = bytes.fromhex(prove(p, 1)["audit_path"][0])
    found = [v for v in range(2000)
             if merkle.leaf_hash(2, commit(ZERO_SALT, b'{"balance": %d}' % v)) == sibling]
    assert found == [777]
    # private records: same kind of guess, nothing matches
    s2, keys, p2 = private_log(tmp_path)
    sibling = bytes.fromhex(prove(p2, 1, keys)["audit_path"][0])
    assert not [v for v in range(900, 1100)
                if merkle.leaf_hash(2, commit(ZERO_SALT, b'{"user": 2, "balance": %d}' % v)) == sibling]


def test_split_key_for_replicas(tmp_path):
    # primary and standby share one public key but never share an epoch,
    # even if both are running at the same time (split brain)
    from sealwal import lms
    kf = tmp_path / "k.json"
    lms.EpochHss(kf, create=True).close()
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    lms.split_keyfile(str(kf), [str(a), str(b)])
    with pytest.raises(RuntimeError):
        lms.EpochHss(kf)
    ka, kb = lms.EpochHss(a), lms.EpochHss(b)
    sa, sb = ka.sign(b"x"), kb.sign(b"x")
    ka.close()
    kb.close()
    assert ka.public_key == kb.public_key
    assert lms.hss_verify(ka.public_key, b"x", sa) and lms.hss_verify(kb.public_key, b"x", sb)
    assert not set(ka.epochs_used) & set(kb.epochs_used)
    assert max(ka.epochs_used) < min(kb.epochs_used)


def test_two_processes_on_one_key_file_never_share_an_epoch(tmp_path):
    import multiprocessing as mp
    from sealwal import lms
    kf = str(tmp_path / "k.json")
    lms.EpochHss(kf, create=True, prefetch=False)
    ctx = mp.get_context("fork")
    q = ctx.Queue()

    def worker():
        k = lms.EpochHss(kf, prefetch=False)
        for _ in range(5):
            k._open_epoch()
        q.put(k.epochs_used)

    ps = [ctx.Process(target=worker) for _ in range(4)]
    for p in ps:
        p.start()
    got = [q.get(timeout=60) for _ in ps]
    for p in ps:
        p.join()
    flat = [e for es in got for e in es]
    assert len(flat) == len(set(flat)) == 24


def test_hss_exhaustion_fails_closed_and_keeps_a_rotation_epoch(tmp_path):
    from sealwal import lms
    kf = str(tmp_path / "k.json")
    lms.EpochHss(kf, create=True, prefetch=False).close()
    a, b = str(tmp_path / "a.json"), str(tmp_path / "b.json")
    lms.split_keyfile(kf, [a, b])
    # leave only two epochs in a's slice: one ordinary, one kept for rotation
    import json as _json
    st = _json.load(open(a))
    st["end_epoch"] = st["next_epoch"] + 2
    lms._save_state(a, st)
    k = lms.EpochHss(a, prefetch=False, low_water=4)
    assert k.low and k.epochs_left() == 0
    msg = b"m"
    while not k._cur[0].exhausted():
        k._cur[0].sign(msg)
    with pytest.raises(lms.SignerExhausted):
        k.sign(msg)
    sig = k.sign_rotation(b"next key: ...")
    assert lms.hss_verify(k.public_key, b"next key: ...", sig)
    with pytest.raises(lms.SignerExhausted):
        k.sign_rotation(b"again")


def test_hss_lock_timeout(tmp_path):
    import fcntl as _f
    from sealwal import lms
    kf = str(tmp_path / "k.json")
    lms.EpochHss(kf, create=True, prefetch=False).close()
    with open(kf + ".lock", "a") as lk:
        _f.flock(lk, _f.LOCK_EX)
        with pytest.raises(lms.SignerUnavailable):
            lms.EpochHss(kf, prefetch=False, lock_timeout=0.05)


def test_async_log_stops_when_signer_runs_out(tmp_path):
    # the commit path fails closed instead of running unsigned forever
    s = make_signer("ed25519")
    calls = {"n": 0}
    real = s.sign

    def flaky(m):
        calls["n"] += 1
        if calls["n"] > 3:
            raise RuntimeError("no epochs left")
        return real(m)
    from sealwal.signers import Signer
    bad = Signer(s.alg, s.public_bytes, s.private_bytes, flaky)
    log = SealedLog.create(tmp_path / "a.wal", bad, sync="none", async_sign=True, max_unsigned=2)
    with pytest.raises(RuntimeError):
        for i in range(50):
            log.append(b"x")
            log.commit()
            time.sleep(0.002)
