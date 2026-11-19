"""Merkle tree over the records of one sealed batch.

The construction follows RFC 9162 (Certificate Transparency v2), section 2.1:

    leaf hash  = SHA-256(0x00 || u64be(lsn) || payload)
    node hash  = SHA-256(0x01 || left || right)

and splits a list of n leaves at the largest power of two smaller than n, so
any batch size works (no padding). The distinct 0x00 / 0x01 prefixes prevent
a leaf from being reinterpreted as an inner node.

An inclusion proof ("audit path") lets someone check that one record belongs
to a batch using only log2(batch size) hashes, without seeing the other
records of the batch.
"""

from __future__ import annotations

import hashlib
import struct

HASH_LEN = 32


def leaf_hash(lsn: int, payload: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + struct.pack(">Q", lsn) + payload).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(leaves: list[bytes]) -> bytes:
    """Merkle tree hash (MTH) of a non-empty list of leaf hashes."""
    if not leaves:
        raise ValueError("a batch must contain at least one record")
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def audit_path(index: int, leaves: list[bytes]) -> list[bytes]:
    """Inclusion proof for leaves[index] (RFC 9162, 2.1.3.1)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(index)
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return audit_path(index, leaves[:k]) + [root(leaves[k:])]
    return audit_path(index - k, leaves[k:]) + [root(leaves[:k])]


def root_from_path(index: int, size: int, leaf: bytes, path: list[bytes]) -> bytes | None:
    """Recompute the root from a leaf and its audit path (RFC 9162, 2.1.3.2).

    Returns None if the path has the wrong shape for (index, size)."""
    if not 0 <= index < size:
        return None
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None
