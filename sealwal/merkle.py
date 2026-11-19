"""History tree over all log records, RFC 9162 (CT v2) style.

    leaf = H(0x00 | u64 lsn | c)      c = commitment to the record
    node = H(0x01 | left | right)

n leaves are split at the largest power of two below n, so any size works.
Every seal signs the root over everything committed so far, which gives
O(log n) inclusion proofs and O(log n) consistency (append-only) proofs
between two signed heads, as in Crosby & Wallach and Certificate Transparency.
Frontier keeps the root up to date with O(log n) memory.
"""

import hashlib
import struct


def leaf_hash(lsn, c):
    return hashlib.sha256(b"\x00" + struct.pack(">Q", lsn) + c).digest()


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n):
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(leaves):
    if not leaves:
        raise ValueError("empty tree")
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def audit_path(index, leaves):
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(index)
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return audit_path(index, leaves[:k]) + [root(leaves[k:])]
    return audit_path(index - k, leaves[k:]) + [root(leaves[:k])]


def root_from_path(index, size, leaf, path):
    """RFC 9162 2.1.3.2. Returns None if the path doesn't fit (index, size)."""
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


class Frontier:
    """Roots of the perfect subtrees along the right edge, (height, hash)."""

    __slots__ = ("_stack", "size")

    def __init__(self):
        self._stack = []
        self.size = 0

    def append(self, leaf):
        self._stack.append((0, leaf))
        self.size += 1
        while len(self._stack) > 1 and self._stack[-1][0] == self._stack[-2][0]:
            h, right = self._stack.pop()
            _, left = self._stack.pop()
            self._stack.append((h + 1, node_hash(left, right)))

    def root(self):
        if not self._stack:
            raise ValueError("empty tree")
        r = self._stack[-1][1]
        for _, left in reversed(self._stack[:-1]):
            r = node_hash(left, r)
        return r

    def copy(self):
        f = Frontier()
        f._stack = list(self._stack)
        f.size = self.size
        return f


def consistency_proof(m, leaves):
    """Proof that the first m leaves form a prefix of all of them (RFC 9162 2.1.4.1)."""
    if not 0 < m <= len(leaves):
        raise ValueError(f"need 0 < m <= n (m={m}, n={len(leaves)})")
    return _subproof(m, leaves, True)


def _subproof(m, leaves, whole):
    n = len(leaves)
    if m == n:
        return [] if whole else [root(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], whole) + [root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root(leaves[:k])]


def verify_consistency(m, n, old_root, new_root, proof):
    """RFC 9162 2.1.4.2."""
    if not 0 < m <= n:
        return False
    if m == n:
        return not proof and old_root == new_root
    if m & (m - 1) == 0:
        proof = [old_root] + list(proof)
    if not proof:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root
