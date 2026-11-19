"""On-disk format of a sealwal log file.

    file   := header frame*
    header := "SEALWAL1" | u16 alg_id | u16 pk_len | public_key | u32 crc32
    frame  := u8 type | u32 body_len | body | u32 crc32(type | body_len | body)

Frame types
-----------
DATA (1)  u64 lsn | payload
SEAL (2)  u64 seal_no | u64 first_lsn | u64 last_lsn | root[32] | prev_digest[32]
          | u16 sig_len | signature            (sig_len may be 0)
SIG  (3)  u64 seal_no | u16 sig_len | signature
          A signature written after the seal it covers (asynchronous signing).

A SEAL closes the batch of DATA frames written since the previous SEAL. Its
digest chains to the previous seal:

    digest_j = SHA-256("sealwal/seal/v1" | seal_no | first_lsn | last_lsn
                       | root | digest_{j-1})

and digest_{-1} (the genesis digest) is bound to the header, so seals cannot
be spliced between logs or re-signed under a different key. A signature over
digest_j therefore authenticates seals 0..j and every record in them.

All integers are big-endian. CRCs only detect torn or corrupted writes; they
are not a security mechanism.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass

MAGIC = b"SEALWAL1"
DATA, SEAL, SIG = 1, 2, 3

_FRAME_HEAD = struct.Struct(">BI")  # type, body_len
_CRC = struct.Struct(">I")
_SEAL_FIXED = struct.Struct(">QQQ32s32sH")
_SIG_FIXED = struct.Struct(">QH")
FRAME_OVERHEAD = _FRAME_HEAD.size + _CRC.size  # 9 bytes


@dataclass(frozen=True)
class Header:
    alg_id: int
    public_key: bytes

    def encode(self) -> bytes:
        body = MAGIC + struct.pack(">HH", self.alg_id, len(self.public_key)) + self.public_key
        return body + _CRC.pack(zlib.crc32(body))

    def genesis_digest(self) -> bytes:
        body = MAGIC + struct.pack(">HH", self.alg_id, len(self.public_key)) + self.public_key
        return hashlib.sha256(b"sealwal/genesis/v1" + body).digest()


def decode_header(buf: bytes) -> tuple[Header, int]:
    """Parse the header at the start of ``buf``; return (header, its length)."""
    if buf[:8] != MAGIC:
        raise ValueError("not a sealwal log (bad magic)")
    alg_id, pk_len = struct.unpack_from(">HH", buf, 8)
    end = 12 + pk_len
    if len(buf) < end + 4:
        raise ValueError("truncated header")
    (crc,) = _CRC.unpack_from(buf, end)
    if zlib.crc32(buf[:end]) != crc:
        raise ValueError("header checksum mismatch")
    return Header(alg_id, bytes(buf[12:end])), end + 4


@dataclass(frozen=True)
class SealRecord:
    seal_no: int
    first_lsn: int
    last_lsn: int
    root: bytes
    prev_digest: bytes
    signature: bytes = b""

    def digest(self) -> bytes:
        return seal_digest(self.seal_no, self.first_lsn, self.last_lsn, self.root, self.prev_digest)


def seal_digest(seal_no: int, first_lsn: int, last_lsn: int, root: bytes, prev: bytes) -> bytes:
    return hashlib.sha256(
        b"sealwal/seal/v1" + struct.pack(">QQQ", seal_no, first_lsn, last_lsn) + root + prev
    ).digest()


def signed_message(digest: bytes) -> bytes:
    """What actually gets signed (domain-separated seal digest)."""
    return b"sealwal/sig/v1" + digest


def _frame(ftype: int, body: bytes) -> bytes:
    head = _FRAME_HEAD.pack(ftype, len(body))
    return head + body + _CRC.pack(zlib.crc32(head + body))


def encode_data(lsn: int, payload: bytes) -> bytes:
    return _frame(DATA, struct.pack(">Q", lsn) + payload)


def encode_seal(s: SealRecord) -> bytes:
    fixed = _SEAL_FIXED.pack(s.seal_no, s.first_lsn, s.last_lsn, s.root, s.prev_digest, len(s.signature))
    return _frame(SEAL, fixed + s.signature)


def encode_sig(seal_no: int, signature: bytes) -> bytes:
    return _frame(SIG, _SIG_FIXED.pack(seal_no, len(signature)) + signature)


class FrameError(Exception):
    """A frame could not be decoded (bad checksum, bad length, truncated)."""


def decode_frame(buf: bytes | memoryview, off: int) -> tuple[int, bytes, int]:
    """Decode the frame starting at ``off``. Returns (type, body, next_offset).

    Raises FrameError if the frame is incomplete or its checksum is wrong."""
    if off + _FRAME_HEAD.size > len(buf):
        raise FrameError("truncated frame header")
    ftype, blen = _FRAME_HEAD.unpack_from(buf, off)
    end = off + _FRAME_HEAD.size + blen
    if end + _CRC.size > len(buf):
        raise FrameError("truncated frame body")
    (crc,) = _CRC.unpack_from(buf, end)
    if zlib.crc32(buf[off:end]) != crc:
        raise FrameError("frame checksum mismatch")
    if ftype not in (DATA, SEAL, SIG):
        raise FrameError(f"unknown frame type {ftype}")
    return ftype, bytes(buf[off + _FRAME_HEAD.size : end]), end + _CRC.size


def parse_data(body: bytes) -> tuple[int, bytes]:
    (lsn,) = struct.unpack_from(">Q", body)
    return lsn, body[8:]


def parse_seal(body: bytes) -> SealRecord:
    seal_no, first, last, root, prev, sig_len = _SEAL_FIXED.unpack_from(body)
    sig = body[_SEAL_FIXED.size :]
    if len(sig) != sig_len:
        raise FrameError("seal signature length mismatch")
    return SealRecord(seal_no, first, last, root, prev, sig)


def parse_sig(body: bytes) -> tuple[int, bytes]:
    seal_no, sig_len = _SIG_FIXED.unpack_from(body)
    sig = body[_SIG_FIXED.size :]
    if len(sig) != sig_len:
        raise FrameError("signature length mismatch")
    return seal_no, sig
