"""Verification and proofs.

verify() replays a log and checks that
  - LSNs are consecutive (nothing missing or reordered),
  - each SEAL closes a non-empty batch, has the next seal number and the
    right LSN range, chains to the previous seal, and its root matches the
    tree over all records so far,
  - every signature (in a SEAL or a later SIG frame) is valid under the
    pinned public key,
  - optionally, an anchor (seal_no, digest) saved somewhere safe is still
    there. Without one you can't tell a rolled-back log from a short one.

Proofs that need only the public key:
  prove / check_proof                record i is under a signed tree head
  prove_consistency / check_consistency
                                     the log at an old seal is a prefix of
                                     the log at a newer signed seal
"""

import os
import struct
from dataclasses import dataclass, field

from . import format as fmt
from . import merkle
from .privacy import ZERO_SALT, Erased, commit
from .signers import ALG_NAMES, verify_signature


@dataclass
class Scan:
    header: fmt.Header
    frames: list            # (offset, type, body, end)
    valid_end: int
    file_size: int
    tail_error: str = None
    mid_corruption: bool = False


def scan(path, start=None, end=None):
    """Decode the header and every frame. With start/end, only the frames in
    that byte range are read (a segment audit must not pay for the whole
    file); start has to be a frame boundary, e.g. the end of a seal."""
    with open(path, "rb") as f:
        if start is None:
            size = os.fstat(f.fileno()).st_size
            buf, base = f.read() if end is None else f.read(end), 0
        else:
            size = os.fstat(f.fileno()).st_size
            head = f.read(min(size, 1 << 16))
        if start is not None:
            f.seek(start)
            buf, base = f.read((end if end is not None else size) - start), start
    header, off = fmt.decode_header(buf if start is None else head)
    if start is not None:
        off = 0
    frames, err, mid = [], None, False
    while off < len(buf):
        try:
            ftype, body, nxt = fmt.decode_frame(buf, off)
        except fmt.FrameError as e:
            err = str(e)
            # A crash only tears the last write, and whatever follows it is
            # junk (half a sector, preallocated space). If a well-formed frame
            # shows up anywhere after the broken one, the damage is in the
            # middle of the log and we must not truncate it away. Inside a
            # segment that ends before the file does, any error is damage.
            mid = _valid_frame_after(buf, off + 1) or (end is not None and base + off < end)
            break
        frames.append((base + off, ftype, body, base + nxt))
        off = nxt
    return Scan(header, frames, base + off, size, err, mid)


def _valid_frame_after(buf, start):
    types = (fmt.DATA, fmt.SEAL, fmt.SIG)
    for i in range(start, len(buf) - 9):
        if buf[i] not in types:
            continue
        try:
            fmt.decode_frame(buf, i)
            return True
        except fmt.FrameError:
            pass
    return False


@dataclass
class SealInfo:
    seal_no: int
    first_lsn: int
    last_lsn: int
    root: bytes
    prev_digest: bytes
    digest: bytes
    end_offset: int

    def as_dict(self):
        return {"seal_no": self.seal_no, "first_lsn": self.first_lsn, "last_lsn": self.last_lsn,
                "root": self.root.hex(), "prev_digest": self.prev_digest.hex()}


@dataclass
class Report:
    ok: bool = True
    alg: str = "none"
    signatures_checked: bool = False
    seals: int = 0
    committed_lsn: int = 0         # last LSN under a seal
    authenticated_lsn: int = 0     # last LSN under a valid signature
    unauthenticated_seals: int = 0
    unsealed_records: int = 0      # after the last seal = uncommitted
    private_records: int = 0
    erased_records: int = 0        # private records whose key was shredded
    contents_checked: bool = False # all readable payloads matched their commitment
    torn_bytes: int = 0
    last_seal_no: int = -1
    last_digest: str = ""
    commit_end_offset: int = 0
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def fail(self, msg):
        self.ok = False
        self.errors.append(msg)


def verify(path, public_key=None, *, trust_header_key=False, anchor=None, keys=None,
           check_contents=True, _state_out=None, start=None, end_offset=None):
    """public_key: the key you expect (pin it; the header's copy can be
    swapped by whoever can write the file). anchor: (seal_no, digest).

    Without keys, only public payloads are checked against their commitments;
    private records are verified structurally (enough for an auditor who
    should not see the data). With keys, private payloads are decrypted and
    checked too, and shredded subjects are counted as erased.

    start/end_offset verify one segment only: start = {"offset", "lsn",
    "seal_no", "prev", "frontier"} is the state right after a seal (taken
    from a witnessed checkpoint, whose cosigned root the frontier must hash
    to; see segment_starts). Segments verify independently, in parallel."""
    rep = Report()
    try:
        sc = scan(path, None if start is None else start["offset"], end_offset)
    except (ValueError, OSError) as e:
        rep.fail(f"cannot read log: {e}")
        return rep

    hdr = sc.header
    rep.alg = ALG_NAMES.get(hdr.alg_id)
    if rep.alg is None:
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
            rep.warnings.append("checked against the key in the header, which isn't pinned")
        else:
            rep.warnings.append("no public key given, signatures NOT checked")
    rep.signatures_checked = key is not None or rep.alg == "none"

    prev = hdr.genesis_digest()
    next_lsn, next_seal = 1, 0
    batch_n, batch_first = 0, None
    tree, committed = merkle.Frontier(), merkle.Frontier()
    digests, seals = [], []
    signed_upto = -1
    frames = sc.frames
    rep.commit_end_offset = frames[0][0] if frames else sc.valid_end
    seal_base = 0
    if start is not None:
        prev, next_lsn, next_seal = start["prev"], start["lsn"], start["seal_no"]
        tree = merkle.Frontier()
        tree._stack, tree.size = list(start["frontier"]), next_lsn - 1
        committed = tree.copy()
        seal_base = next_seal
        digests = [None] * next_seal
        rep.commit_end_offset = start["offset"]

    def sig_ok(seal_no, sig):
        if key is None:
            return True
        return verify_signature(rep.alg, key, sig, fmt.signed_message(digests[seal_no]))

    for off, ftype, body, end in frames:
        try:
            parsed = (fmt.parse_data(body) if ftype == fmt.DATA else
                      fmt.parse_seal(body) if ftype == fmt.SEAL else fmt.parse_sig(body))
        except (struct.error, fmt.FrameError):
            rep.fail(f"offset {off}: malformed frame")
            break
        if ftype == fmt.DATA:
            lsn, subject, c, data = parsed
            if lsn != next_lsn:
                rep.fail(f"offset {off}: expected LSN {next_lsn}, found {lsn}")
                break
            if check_contents:
                bad = _check_record(lsn, subject, c, data, keys, rep)
                if bad:
                    rep.fail(f"offset {off}: {bad}")
                    break
            if batch_first is None:
                batch_first = lsn
            tree.append(merkle.leaf_hash(lsn, c))
            batch_n += 1
            next_lsn += 1

        elif ftype == fmt.SEAL:
            s = parsed
            where = f"offset {off}: seal #{s.seal_no}"
            if s.seal_no != next_seal:
                rep.fail(f"offset {off}: expected seal #{next_seal}, found #{s.seal_no}")
                break
            if not batch_n:
                rep.fail(f"{where} closes an empty batch")
                break
            if (s.first_lsn, s.last_lsn) != (batch_first, next_lsn - 1):
                rep.fail(f"{where} claims LSNs {s.first_lsn}-{s.last_lsn}, "
                         f"batch has {batch_first}-{next_lsn - 1}")
                break
            if s.prev_digest != prev:
                rep.fail(f"{where} does not chain to the previous seal")
                break
            if tree.root() != s.root:
                rep.fail(f"{where} Merkle root mismatch (records modified)")
                break
            prev = s.digest()
            digests.append(prev)
            if s.signature:
                if not sig_ok(s.seal_no, s.signature):
                    rep.fail(f"{where} has an invalid signature")
                    break
                signed_upto = s.seal_no
            seals.append(SealInfo(s.seal_no, s.first_lsn, s.last_lsn, s.root, s.prev_digest, prev, end))
            committed = tree.copy()
            next_seal += 1
            batch_n, batch_first = 0, None
            rep.commit_end_offset = end

        elif ftype == fmt.SIG:
            seal_no, sig = parsed
            if seal_no < seal_base:
                continue          # belongs to the previous segment
            if not 0 <= seal_no < len(digests):
                rep.fail(f"offset {off}: signature for unknown seal #{seal_no}")
                break
            if not sig_ok(seal_no, sig):
                rep.fail(f"offset {off}: invalid signature on seal #{seal_no}")
                break
            signed_upto = max(signed_upto, seal_no)
            if not batch_n:
                rep.commit_end_offset = end

    rep.seals = len(seals)
    rep.unsealed_records = batch_n
    rep.contents_checked = check_contents and (keys is not None or rep.private_records == 0)
    rep.torn_bytes = sc.file_size - sc.valid_end
    if seals:
        rep.committed_lsn = seals[-1].last_lsn
        rep.last_seal_no = seals[-1].seal_no
        rep.last_digest = seals[-1].digest.hex()
    if rep.alg == "none":
        rep.unauthenticated_seals = len(seals)
    else:
        if signed_upto >= seal_base:
            rep.authenticated_lsn = seals[signed_upto - seal_base].last_lsn
        rep.unauthenticated_seals = len(seals) - 1 - (signed_upto - seal_base)

    if sc.mid_corruption:
        rep.fail(f"offset {sc.valid_end}: corrupted frame in the middle of the log ({sc.tail_error})")
    elif sc.tail_error and rep.ok:
        rep.warnings.append(f"ignored a torn tail of {rep.torn_bytes} bytes ({sc.tail_error})")
    if rep.unsealed_records:
        rep.warnings.append(f"{rep.unsealed_records} records after the last seal (uncommitted)")
    if rep.alg != "none" and rep.unauthenticated_seals > 0 and rep.ok:
        rep.warnings.append(f"{rep.unauthenticated_seals} seal(s) at the end not signed yet")

    if anchor is not None and rep.ok:
        a_no, a_digest = anchor
        if a_no >= len(seals):
            rep.fail(f"rollback: anchored seal #{a_no} is missing (log ends at #{rep.last_seal_no})")
        elif seals[a_no].digest != a_digest:
            rep.fail(f"anchored seal #{a_no} has a different digest (log was rewritten)")

    if _state_out is not None:
        _state_out["seals"] = seals
        _state_out["tree"] = committed
    return rep


def _check_record(lsn, subject, c, data, keys, rep):
    if subject == 0:
        if commit(ZERO_SALT, data) != c:
            return f"record {lsn} does not match its commitment (modified)"
        return None
    rep.private_records += 1
    if keys is None:
        return None
    try:
        salt, payload = keys.open(subject, lsn, data)
    except Erased:
        rep.erased_records += 1
        return None
    except ValueError as e:
        return str(e)
    if commit(salt, payload) != c:
        return f"record {lsn} does not match its commitment (modified)"
    return None


def read_records(path, keys=None):
    """Yield (lsn, subject, payload) for committed records. payload is None
    for private records you can't open (no keys, or the subject was erased)."""
    st = {}
    rep = verify(path, trust_header_key=True, keys=keys, _state_out=st)
    if not rep.ok:
        raise ValueError("log does not verify: " + "; ".join(rep.errors))
    for _, ftype, body, _ in scan(path).frames:
        if ftype != fmt.DATA:
            continue
        lsn, subject, c, data = fmt.parse_data(body)
        if lsn > rep.committed_lsn:
            break
        if subject == 0:
            yield lsn, 0, data
            continue
        payload = None
        if keys is not None:
            try:
                payload = keys.open(subject, lsn, data)[1]
            except Erased:
                pass
        yield lsn, subject, payload


def _load(path, keys=None):
    st = {}
    rep = verify(path, trust_header_key=True, keys=keys, _state_out=st)
    if not rep.ok:
        raise ValueError("log does not verify: " + "; ".join(rep.errors))
    leaves, payloads, sigs = [], {}, {}
    for _, ftype, body, _ in scan(path).frames:
        if ftype == fmt.DATA:
            lsn, subject, c, data = fmt.parse_data(body)
            leaves.append(merkle.leaf_hash(lsn, c))
            payloads[lsn] = (subject, c, data)
        elif ftype == fmt.SEAL:
            s = fmt.parse_seal(body)
            if s.signature:
                sigs.setdefault(s.seal_no, s.signature)
        else:
            n, sig = fmt.parse_sig(body)
            sigs.setdefault(n, sig)
    return rep, st["seals"], leaves[:rep.committed_lsn], payloads, sigs


def prove(path, lsn, keys=None, reveal=True):
    """Provenance receipt for one record: its opening (payload + salt), the
    audit path to the first signed tree head covering it, that head and its
    signature. Siblings in the path are salted commitments, so the receipt
    says nothing about other private records. reveal=False leaves out the
    opening: then it only proves *some* record sits at that position.
    O(log n) hashes and one signature."""
    rep, seals, leaves, payloads, sigs = _load(path, keys)
    target = next((s for s in seals if s.first_lsn <= lsn <= s.last_lsn), None)
    if target is None:
        raise KeyError(f"LSN {lsn} is not committed")
    if rep.alg == "none":
        head_no = target.seal_no
    else:
        later = sorted(n for n in sigs if n >= target.seal_no)
        if not later:
            raise KeyError(f"seal #{target.seal_no} is not signed yet")
        head_no = later[0]
    head = seals[head_no]
    subject, c, data = payloads[lsn]
    opening = None
    if reveal:
        if subject == 0:
            opening = {"salt": ZERO_SALT.hex(), "payload": data.hex()}
        else:
            if keys is None:
                raise KeyError("private record: pass keys=... to reveal it")
            salt, payload = keys.open(subject, lsn, data)   # raises Erased
            opening = {"salt": salt.hex(), "payload": payload.hex()}
    return {
        "format": "sealwal-receipt-v1",
        "alg": rep.alg,
        "lsn": lsn,
        "subject": subject,
        "commitment": c.hex(),
        "opening": opening,
        "tree_size": head.last_lsn,
        "audit_path": [h.hex() for h in merkle.audit_path(lsn - 1, leaves[:head.last_lsn])],
        "seal": head.as_dict(),
        "signature": sigs.get(head_no, b"").hex(),
    }


def _digest_of(d):
    return fmt.seal_digest(d["seal_no"], d["first_lsn"], d["last_lsn"],
                           bytes.fromhex(d["root"]), bytes.fromhex(d["prev_digest"]))


def check_proof(proof, public_key):
    if proof.get("format") != "sealwal-receipt-v1":
        return False, "unknown proof format"
    seal, lsn, size = proof["seal"], proof["lsn"], proof["tree_size"]
    if size != seal["last_lsn"] or not 1 <= lsn <= size:
        return False, "tree size doesn't match the seal, or LSN outside the tree"
    c = bytes.fromhex(proof["commitment"])
    op = proof.get("opening")
    if op is not None and commit(bytes.fromhex(op["salt"]), bytes.fromhex(op["payload"])) != c:
        return False, "opening doesn't match the commitment"
    leaf = merkle.leaf_hash(lsn, c)
    r = merkle.root_from_path(lsn - 1, size, leaf, [bytes.fromhex(h) for h in proof["audit_path"]])
    if r is None or r.hex() != seal["root"]:
        return False, "audit path doesn't lead to the signed tree head"
    if not verify_signature(proof["alg"], public_key, bytes.fromhex(proof["signature"]),
                            fmt.signed_message(_digest_of(seal))):
        return False, "bad signature"
    what = "record" if op is not None else "a committed record (contents not revealed)"
    return True, f"{what} {lsn} is in the log under signed seal #{seal['seal_no']} (size {size})"


def prove_consistency(path, old_seal, new_seal=None):
    """The log at old_seal is a prefix of the log at new_seal (default: the
    newest signed seal)."""
    rep, seals, leaves, _, sigs = _load(path)
    if not 0 <= old_seal < len(seals):
        raise KeyError(f"no seal #{old_seal}")
    if new_seal is None:
        new_seal = max(sigs) if sigs and rep.alg != "none" else len(seals) - 1
    if not old_seal <= new_seal < len(seals):
        raise KeyError("need old_seal <= new_seal")
    if rep.alg != "none" and new_seal not in sigs:
        raise KeyError(f"seal #{new_seal} has no signature")
    old, new = seals[old_seal], seals[new_seal]
    return {
        "format": "sealwal-consistency-v1",
        "alg": rep.alg,
        "old": old.as_dict(),
        "new": new.as_dict(),
        "new_signature": sigs.get(new_seal, b"").hex(),
        "proof": [h.hex() for h in merkle.consistency_proof(old.last_lsn, leaves[:new.last_lsn])],
    }


def check_consistency(proof, public_key, trusted_old_digest=None):
    """trusted_old_digest: the digest of the old seal as you saved it back
    then. Without it you only learn that the two heads agree with each other."""
    if proof.get("format") != "sealwal-consistency-v1":
        return False, "unknown proof format"
    old, new = proof["old"], proof["new"]
    if trusted_old_digest is not None and _digest_of(old) != trusted_old_digest:
        return False, "old tree head is not the one you anchored"
    if not verify_signature(proof["alg"], public_key, bytes.fromhex(proof["new_signature"]),
                            fmt.signed_message(_digest_of(new))):
        return False, "bad signature on the new tree head"
    m, n = old["last_lsn"], new["last_lsn"]
    if not merkle.verify_consistency(m, n, bytes.fromhex(old["root"]), bytes.fromhex(new["root"]),
                                     [bytes.fromhex(h) for h in proof["proof"]]):
        return False, f"size {n} does not extend size {m}, history was rewritten"
    return True, f"log only grew, {m} -> {n} records (seal #{old['seal_no']} -> #{new['seal_no']})"
