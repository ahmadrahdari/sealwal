"""Reading, verifying and proving membership in a sealwal log.

``verify()`` replays a log file and checks, in order:

1. every DATA frame has the next LSN (no gaps, no reordering);
2. every SEAL closes a non-empty batch, carries the next seal number, the
   right LSN range, the Merkle root of exactly those records, and the digest
   of the previous seal (so whole batches cannot be dropped or reordered);
3. every signature (inline in a SEAL, or in a later SIG frame) is valid under
   the pinned public key, which authenticates the seal chain up to that point;
4. optionally, that an externally stored *anchor* (seal number + digest) is
   present, which is the only way to detect a rollback that deletes the most
   recent sealed batches.

``prove()`` produces a compact inclusion proof for one record, which
``check_proof()`` verifies with nothing but the public key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import format as fmt
from . import merkle
from .signers import ALG_NAMES, verify_signature


@dataclass
class Scan:
    header: fmt.Header
    frames: list[tuple[int, int, bytes, int]]  # (offset, type, body, end_offset)
    valid_end: int
    file_size: int
    tail_error: str | None  # decode problem at valid_end, if any
    mid_log_corruption: bool  # a bad frame followed by more bytes


def scan(path: str | os.PathLike) -> Scan:
    """Decode all frames; stop at the first one that does not decode."""
    with open(path, "rb") as f:
        buf = f.read()
    header, off = fmt.decode_header(buf)
    frames = []
    tail_error = None
    mid = False
    while off < len(buf):
        try:
            ftype, body, end = fmt.decode_frame(buf, off)
        except fmt.FrameError as e:
            tail_error = str(e)
            # A crash can only tear the *last* write. If the bad frame's
            # declared length ends before EOF, something in the middle of the
            # log was modified.
            if len(buf) - off >= 5:
                blen = int.from_bytes(buf[off + 1 : off + 5], "big")
                declared_end = off + 5 + blen + 4
                mid = declared_end < len(buf)
            break
        frames.append((off, ftype, body, end))
        off = end
    return Scan(header, frames, off, len(buf), tail_error, mid)


@dataclass
class SealInfo:
    seal_no: int
    first_lsn: int
    last_lsn: int
    root: bytes
    prev_digest: bytes
    digest: bytes
    end_offset: int


@dataclass
class Report:
    ok: bool = True
    alg: str = "none"
    signatures_checked: bool = False
    seals: int = 0
    committed_lsn: int = 0  # last LSN covered by a seal
    authenticated_lsn: int = 0  # last LSN covered by a valid signature
    unauthenticated_seals: int = 0  # seals after the last valid signature
    unsealed_records: int = 0  # DATA frames after the last seal (uncommitted)
    torn_bytes: int = 0  # undecodable bytes at the end of the file
    last_seal_no: int = -1
    last_digest: str = ""
    commit_end_offset: int = 0  # file offset just after the committed prefix
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def fail(self, msg: str) -> None:
        self.ok = False
        self.errors.append(msg)


def verify(
    path: str | os.PathLike,
    public_key: bytes | None = None,
    *,
    trust_header_key: bool = False,
    anchor: tuple[int, bytes] | None = None,
    _seals_out: list | None = None,
) -> Report:
    """Verify a log file. See the module docstring for what is checked.

    public_key        The key you expect the log to be signed with (pinned out
                      of band). Strongly recommended: the key stored in the
                      header is attacker-controlled if the file is.
    trust_header_key  Use the header's key when no key is pinned.
    anchor            (seal_no, digest) recorded somewhere the attacker cannot
                      write, e.g. after each checkpoint. Detects rollback.
    """
    rep = Report()
    try:
        sc = scan(path)
    except (ValueError, OSError) as e:
        rep.fail(f"cannot read log: {e}")
        return rep

    hdr = sc.header
    rep.alg = ALG_NAMES.get(hdr.alg_id, f"unknown({hdr.alg_id})")
    if rep.alg.startswith("unknown"):
        rep.fail(f"unknown signature algorithm id {hdr.alg_id}")
        return rep

    key = None
    if rep.alg != "none":
        if public_key is not None:
            if public_key != hdr.public_key:
                rep.fail("header public key does not match the pinned key")
                return rep
            key = public_key
        elif trust_header_key:
            key = hdr.public_key
            rep.warnings.append("signatures checked against the header key, which is not pinned")
        else:
            rep.warnings.append("no public key given: signatures NOT checked")
    rep.signatures_checked = key is not None or rep.alg == "none"

    prev = hdr.genesis_digest()
    next_lsn, next_seal = 1, 0
    batch: list[bytes] = []
    batch_first = None
    digests: list[bytes] = []
    authenticated_seal = -1
    seals: list[SealInfo] = []
    rep.commit_end_offset = sc.frames[0][0] if sc.frames else sc.valid_end

    def check_sig(seal_no: int, sig: bytes) -> bool:
        if key is None:
            return True
        return verify_signature(rep.alg, key, sig, fmt.signed_message(digests[seal_no]))

    for off, ftype, body, end in sc.frames:
        if ftype == fmt.DATA:
            lsn, payload = fmt.parse_data(body)
            if lsn != next_lsn:
                rep.fail(f"offset {off}: expected LSN {next_lsn}, found {lsn}")
                break
            if batch_first is None:
                batch_first = lsn
            batch.append(merkle.leaf_hash(lsn, payload))
            next_lsn += 1
        elif ftype == fmt.SEAL:
            s = fmt.parse_seal(body)
            if s.seal_no != next_seal:
                rep.fail(f"offset {off}: expected seal #{next_seal}, found #{s.seal_no}")
                break
            if not batch:
                rep.fail(f"offset {off}: seal #{s.seal_no} closes an empty batch")
                break
            if (s.first_lsn, s.last_lsn) != (batch_first, next_lsn - 1):
                rep.fail(
                    f"offset {off}: seal #{s.seal_no} claims LSNs {s.first_lsn}-{s.last_lsn}, "
                    f"batch holds {batch_first}-{next_lsn - 1}"
                )
                break
            if s.prev_digest != prev:
                rep.fail(f"offset {off}: seal #{s.seal_no} does not chain to the previous seal")
                break
            if merkle.root(batch) != s.root:
                rep.fail(f"offset {off}: seal #{s.seal_no} Merkle root mismatch (records modified)")
                break
            prev = s.digest()
            digests.append(prev)
            if s.signature:
                if not check_sig(s.seal_no, s.signature):
                    rep.fail(f"offset {off}: invalid signature on seal #{s.seal_no}")
                    break
                authenticated_seal = s.seal_no
            seals.append(SealInfo(s.seal_no, s.first_lsn, s.last_lsn, s.root, s.prev_digest, prev, end))
            next_seal += 1
            batch, batch_first = [], None
            rep.commit_end_offset = end
        elif ftype == fmt.SIG:
            seal_no, sig = fmt.parse_sig(body)
            if not 0 <= seal_no < len(digests):
                rep.fail(f"offset {off}: signature for unknown seal #{seal_no}")
                break
            if not check_sig(seal_no, sig):
                rep.fail(f"offset {off}: invalid signature on seal #{seal_no}")
                break
            authenticated_seal = max(authenticated_seal, seal_no)
            if not batch:
                rep.commit_end_offset = end

    rep.seals = len(seals)
    rep.unsealed_records = len(batch)
    rep.torn_bytes = sc.file_size - sc.valid_end
    if seals:
        rep.committed_lsn = seals[-1].last_lsn
        rep.last_seal_no = seals[-1].seal_no
        rep.last_digest = seals[-1].digest.hex()
    if rep.alg == "none":
        authenticated_seal = -1
    # (if no key was given, authenticated_seal reflects where signatures are
    # present but unchecked; rep.signatures_checked is False in that case)
    if authenticated_seal >= 0:
        rep.authenticated_lsn = seals[authenticated_seal].last_lsn
    rep.unauthenticated_seals = len(seals) - 1 - authenticated_seal if rep.alg != "none" else len(seals)

    if sc.mid_log_corruption:
        rep.fail(f"offset {sc.valid_end}: corrupted frame in the middle of the log ({sc.tail_error})")
    elif sc.tail_error and rep.ok:
        rep.warnings.append(f"torn tail of {rep.torn_bytes} bytes ignored ({sc.tail_error})")
    if rep.unsealed_records:
        rep.warnings.append(f"{rep.unsealed_records} records after the last seal are uncommitted")
    if rep.alg != "none" and rep.unauthenticated_seals > 0 and rep.ok:
        rep.warnings.append(f"{rep.unauthenticated_seals} seal(s) at the tail are not yet signed")

    if anchor is not None and rep.ok:
        a_no, a_digest = anchor
        if a_no >= len(seals):
            rep.fail(f"rollback: anchored seal #{a_no} is missing (log ends at #{rep.last_seal_no})")
        elif seals[a_no].digest != a_digest:
            rep.fail(f"anchored seal #{a_no} has a different digest (log was rewritten)")

    if _seals_out is not None:
        _seals_out.extend(seals)
    return rep


# --------------------------------------------------------------------------
# Inclusion proofs
# --------------------------------------------------------------------------


def prove(path: str | os.PathLike, lsn: int) -> dict:
    """Build a self-contained proof that record ``lsn`` is in the log.

    The proof contains the record, its Merkle audit path inside its batch,
    the seal headers from its batch up to the first signed seal, and that
    signature. Size: O(log batch_size) hashes plus one signature, plus one
    seal header per unsigned seal in between (bounded by the signing interval).
    """
    sc = scan(path)
    seals: list[SealInfo] = []
    rep = verify(path, trust_header_key=True, _seals_out=seals)
    if not rep.ok:
        raise ValueError("log does not verify: " + "; ".join(rep.errors))

    target = next((s for s in seals if s.first_lsn <= lsn <= s.last_lsn), None)
    if target is None:
        raise KeyError(f"LSN {lsn} is not in a committed batch")

    leaves, payload = [], None
    sigs: dict[int, bytes] = {}
    for _off, ftype, body, _end in sc.frames:
        if ftype == fmt.DATA:
            rec_lsn, rec_payload = fmt.parse_data(body)
            if target.first_lsn <= rec_lsn <= target.last_lsn:
                leaves.append(merkle.leaf_hash(rec_lsn, rec_payload))
                if rec_lsn == lsn:
                    payload = rec_payload
        elif ftype == fmt.SEAL:
            s = fmt.parse_seal(body)
            if s.signature:
                sigs.setdefault(s.seal_no, s.signature)
        elif ftype == fmt.SIG:
            seal_no, sig = fmt.parse_sig(body)
            sigs.setdefault(seal_no, sig)

    signed = sorted(n for n in sigs if n >= target.seal_no)
    if rep.alg != "none" and not signed:
        raise KeyError(f"seal #{target.seal_no} is not yet covered by a signature")
    upto = signed[0] if signed else target.seal_no
    idx = lsn - target.first_lsn
    return {
        "format": "sealwal-proof-v1",
        "alg": rep.alg,
        "lsn": lsn,
        "payload": payload.hex(),
        "leaf_index": idx,
        "batch_size": len(leaves),
        "audit_path": [h.hex() for h in merkle.audit_path(idx, leaves)],
        "seals": [
            {
                "seal_no": s.seal_no,
                "first_lsn": s.first_lsn,
                "last_lsn": s.last_lsn,
                "root": s.root.hex(),
                "prev_digest": s.prev_digest.hex(),
            }
            for s in seals[target.seal_no : upto + 1]
        ],
        "signature": sigs.get(upto, b"").hex(),
    }


def check_proof(proof: dict, public_key: bytes) -> tuple[bool, str]:
    """Verify a proof from ``prove()``. Returns (ok, reason)."""
    if proof.get("format") != "sealwal-proof-v1":
        return False, "unknown proof format"
    seals = proof["seals"]
    if not seals:
        return False, "no seals in proof"
    first = seals[0]
    lsn = proof["lsn"]
    if not first["first_lsn"] <= lsn <= first["last_lsn"]:
        return False, "record LSN outside the sealed range"
    if proof["batch_size"] != first["last_lsn"] - first["first_lsn"] + 1:
        return False, "batch size does not match the seal"
    if proof["leaf_index"] != lsn - first["first_lsn"]:
        return False, "leaf index does not match the LSN"
    leaf = merkle.leaf_hash(lsn, bytes.fromhex(proof["payload"]))
    path = [bytes.fromhex(h) for h in proof["audit_path"]]
    root = merkle.root_from_path(proof["leaf_index"], proof["batch_size"], leaf, path)
    if root is None or root.hex() != first["root"]:
        return False, "audit path does not lead to the sealed Merkle root"
    digest = None
    for i, s in enumerate(seals):
        prev = bytes.fromhex(s["prev_digest"])
        if i > 0 and (prev != digest or s["seal_no"] != seals[i - 1]["seal_no"] + 1):
            return False, f"seal chain broken at seal #{s['seal_no']}"
        digest = fmt.seal_digest(s["seal_no"], s["first_lsn"], s["last_lsn"], bytes.fromhex(s["root"]), prev)
    sig = bytes.fromhex(proof["signature"])
    if not verify_signature(proof["alg"], public_key, sig, fmt.signed_message(digest)):
        return False, "signature does not verify under the given key"
    return True, f"record {lsn} is included under signed seal #{seals[-1]['seal_no']}"
