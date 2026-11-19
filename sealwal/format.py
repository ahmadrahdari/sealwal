"""On-disk format.

    file   = header frame*
    header = "SEALWAL3" | u16 alg | u16 pk_len | public key | u32 crc
    frame  = u8 type | u32 len | body | u32 crc(type | len | body)

    DATA  u64 lsn | u32 subject | c[32] | body
          c = commitment to the payload (see privacy.py); body is the
          plaintext for public records (subject 0), AES-GCM otherwise
    SEAL  u64 seal_no | u64 first_lsn | u64 last_lsn | root[32] | prev[32]
          | u16 sig_len | sig            (sig may be empty)
    SIG   u64 seal_no | u16 sig_len | sig   (signature written later)

`root` is the Merkle root over all records 1..last_lsn, i.e. a tree head.
Leaves are built from (lsn, c) only, so the tree never sees a payload.
Each seal is hashed together with the previous seal's digest, and the very
first one chains to a digest of the header, so you can't splice seals from
another log or swap the key. A signature on seal j covers everything up to j.

All integers big-endian. The CRCs are only there to spot torn writes.
"""

import hashlib
import struct
import zlib
from dataclasses import dataclass

MAGIC = b"SEALWAL3"
DATA, SEAL, SIG = 1, 2, 3

_HEAD = struct.Struct(">BI")
_CRC = struct.Struct(">I")
_SEAL = struct.Struct(">QQQ32s32sH")
_SIGF = struct.Struct(">QH")
_DATA = struct.Struct(">QI32s")


@dataclass(frozen=True)
class Header:
    alg_id: int
    public_key: bytes

    def _body(self):
        return MAGIC + struct.pack(">HH", self.alg_id, len(self.public_key)) + self.public_key

    def encode(self):
        b = self._body()
        return b + _CRC.pack(zlib.crc32(b))

    def genesis_digest(self):
        return hashlib.sha256(b"sealwal/genesis/v2" + self._body()).digest()


def decode_header(buf):
    if buf[:8] != MAGIC:
        raise ValueError("not a sealwal v3 log")
    alg, klen = struct.unpack_from(">HH", buf, 8)
    end = 12 + klen
    if len(buf) < end + 4:
        raise ValueError("truncated header")
    if zlib.crc32(buf[:end]) != _CRC.unpack_from(buf, end)[0]:
        raise ValueError("header checksum mismatch")
    return Header(alg, bytes(buf[12:end])), end + 4


def seal_digest(seal_no, first, last, root, prev):
    return hashlib.sha256(b"sealwal/seal/v2" + struct.pack(">QQQ", seal_no, first, last)
                          + root + prev).digest()


def signed_message(digest):
    return b"sealwal/sig/v2" + digest


@dataclass(frozen=True)
class SealRecord:
    seal_no: int
    first_lsn: int
    last_lsn: int
    root: bytes
    prev_digest: bytes
    signature: bytes = b""

    def digest(self):
        return seal_digest(self.seal_no, self.first_lsn, self.last_lsn, self.root, self.prev_digest)


class FrameError(Exception):
    pass


def _frame(ftype, body):
    head = _HEAD.pack(ftype, len(body))
    return head + body + _CRC.pack(zlib.crc32(head + body))


def data_body(lsn, subject, c, body):
    return _DATA.pack(lsn, subject, c) + body


def encode_data(lsn, subject, c, body):
    return _frame(DATA, data_body(lsn, subject, c, body))


def encode_seal(s):
    return _frame(SEAL, _SEAL.pack(s.seal_no, s.first_lsn, s.last_lsn, s.root, s.prev_digest,
                                   len(s.signature)) + s.signature)


def encode_sig(seal_no, sig):
    return _frame(SIG, _SIGF.pack(seal_no, len(sig)) + sig)


def decode_frame(buf, off):
    """-> (type, body, next offset). FrameError if incomplete or corrupt."""
    if off + _HEAD.size > len(buf):
        raise FrameError("truncated frame header")
    ftype, blen = _HEAD.unpack_from(buf, off)
    end = off + _HEAD.size + blen
    if end + 4 > len(buf):
        raise FrameError("truncated frame body")
    if zlib.crc32(buf[off:end]) != _CRC.unpack_from(buf, end)[0]:
        raise FrameError("frame checksum mismatch")
    if ftype not in (DATA, SEAL, SIG):
        raise FrameError(f"unknown frame type {ftype}")
    return ftype, bytes(buf[off + _HEAD.size:end]), end + 4


def parse_data(body):
    """-> (lsn, subject, commitment, body)"""
    lsn, subject, c = _DATA.unpack_from(body)
    return lsn, subject, c, body[_DATA.size:]


def parse_seal(body):
    seal_no, first, last, root, prev, n = _SEAL.unpack_from(body)
    sig = body[_SEAL.size:]
    if len(sig) != n:
        raise FrameError("bad signature length in seal")
    return SealRecord(seal_no, first, last, root, prev, sig)


def parse_sig(body):
    seal_no, n = _SIGF.unpack_from(body)
    sig = body[_SIGF.size:]
    if len(sig) != n:
        raise FrameError("bad signature length")
    return seal_no, sig
