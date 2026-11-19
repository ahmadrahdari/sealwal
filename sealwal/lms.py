"""Stateful hash-based signatures (LMS/HSS, RFC 8554) with recovery epochs.

Parameters: LMOTS_SHA256_N32_W4 and LMS_SHA256_M32_H10, two HSS levels.
The hash chains run in C (csrc/lmots.c); this file does the rest.

The hard part of LMS is state: a one-time key must never sign twice, so
normally every signature needs a durable state update. Here the state is
split in two:

  level 0 (top tree)    leaf index = epoch. The epoch counter lives in the
                        key file and is bumped durably *before* an epoch is
                        used. One fsync per epoch, not per signature.
  level 1 (epoch tree)  leaf index = position inside the epoch. Kept in
                        memory only. After a crash we never resume an epoch;
                        we open a new one and throw the rest away.

So a crash can waste up to 1023 leaves, but it can never reuse one, and the
commit path pays no state write. The next epoch tree is built in a
background thread while the current one is still in use (ctypes drops the
GIL during the C calls).

The key file holds the master seed and the epoch counter, so it must not be
restored from an old backup. The log itself can be: epochs never come from
the log.

Note: follows the RFC 8554 algorithms but was not checked against the
official test vectors.
"""

import ctypes
import hashlib
import fcntl
import json
import os
import struct
import threading

try:
    _lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "_lmots.so"))
except OSError as e:
    raise ImportError("sealwal/_lmots.so not found, build it first: make -C csrc") from e
for _f in ("ots_keygen", "ots_sign", "ots_candidate", "lms_tree"):
    getattr(_lib, _f).restype = None

LMOTS_W4 = 3
LMS_H5, LMS_H10, LMS_H15 = 5, 6, 7
_HEIGHT = {LMS_H5: 5, LMS_H10: 10, LMS_H15: 15}
P = 67
D_MESG = 0x8181
D_LEAF = 0x8282
D_INTR = 0x8383

OTS_SIG_LEN = 4 + 32 + 32 * P
LMS_PUB_LEN = 4 + 4 + 16 + 32


def _sha(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _msg_digest(I, q, C, msg):
    Q = _sha(I, struct.pack(">IH", q, D_MESG), C, msg)
    total = sum(15 - ((Q[i // 2] >> (0 if i % 2 else 4)) & 0xF) for i in range(64))
    return Q + struct.pack(">H", total << 4)


# ---------------------------------------------------------------- LMS


class LmsTree:
    """One LMS key pair (a full tree kept in memory)."""

    def __init__(self, I, seed, h=10):
        self.I, self.seed, self.h = I, seed, h
        self.type = {5: LMS_H5, 10: LMS_H10, 15: LMS_H15}[h]
        buf = ctypes.create_string_buffer(32 * (2 << h))
        _lib.lms_tree(I, seed, h, buf)
        self._T = buf.raw
        self.root = self._T[32:64]
        self.next = 0

    def node(self, r):
        return self._T[32 * r: 32 * r + 32]

    def public_key(self):
        return struct.pack(">II", self.type, LMOTS_W4) + self.I + self.root

    def exhausted(self):
        return self.next >= (1 << self.h)

    def sign(self, msg):
        q = self.next
        if q >= (1 << self.h):
            raise RuntimeError("LMS tree exhausted")
        self.next += 1
        C = os.urandom(32)
        V = _msg_digest(self.I, q, C, msg)
        Y = ctypes.create_string_buffer(32 * P)
        _lib.ots_sign(self.I, q, self.seed, V, Y)
        r = (1 << self.h) + q
        path = b"".join(self.node((r >> i) ^ 1) for i in range(self.h))
        return (struct.pack(">II", q, LMOTS_W4) + C + Y.raw
                + struct.pack(">I", self.type) + path)


def lms_sig_len(lms_type):
    return 4 + OTS_SIG_LEN + 4 + 32 * _HEIGHT[lms_type]


def lms_verify(pub, msg, sig):
    if len(pub) != LMS_PUB_LEN:
        return False
    lms_type, ots_type = struct.unpack(">II", pub[:8])
    if ots_type != LMOTS_W4 or lms_type not in _HEIGHT:
        return False
    I, T1 = pub[8:24], pub[24:56]
    h = _HEIGHT[lms_type]
    if len(sig) != lms_sig_len(lms_type):
        return False
    q, sig_ots_type = struct.unpack(">II", sig[:8])
    if sig_ots_type != LMOTS_W4 or q >= (1 << h):
        return False
    C, Y = sig[8:40], sig[40:40 + 32 * P]
    off = 40 + 32 * P
    if struct.unpack(">I", sig[off:off + 4])[0] != lms_type:
        return False
    path = sig[off + 4:]
    V = _msg_digest(I, q, C, msg)
    Kc = ctypes.create_string_buffer(32)
    _lib.ots_candidate(I, q, V, Y, Kc)
    node = (1 << h) + q
    tmp = _sha(I, struct.pack(">IH", node, D_LEAF), Kc.raw)
    for i in range(h):
        sib = path[32 * i: 32 * i + 32]
        parent = struct.pack(">IH", node >> 1, D_INTR)
        tmp = _sha(I, parent, sib, tmp) if node & 1 else _sha(I, parent, tmp, sib)
        node >>= 1
    return tmp == T1


# ---------------------------------------------------------------- HSS


def hss_verify(pub, msg, sig):
    """Two-level HSS verification."""
    if len(pub) != 4 + LMS_PUB_LEN or struct.unpack(">I", pub[:4])[0] != 2:
        return False
    pub0 = pub[4:]
    if len(sig) < 4 or struct.unpack(">I", sig[:4])[0] != 1:
        return False
    try:
        len0 = lms_sig_len(struct.unpack(">I", pub0[:4])[0])
        sig0 = sig[4:4 + len0]
        pub1 = sig[4 + len0:4 + len0 + LMS_PUB_LEN]
        len1 = lms_sig_len(struct.unpack(">I", pub1[:4])[0])
        sig1 = sig[4 + len0 + LMS_PUB_LEN:]
    except (KeyError, struct.error):
        return False
    if len(sig1) != len1:
        return False
    return lms_verify(pub0, pub1, sig0) and lms_verify(pub1, msg, sig1)


class EpochHss:
    """HSS key whose top-level index is a durable epoch counter."""

    def __init__(self, keyfile, h0=10, h1=10, create=False, prefetch=True):
        self.keyfile = os.fspath(keyfile)
        if create:
            if os.path.exists(self.keyfile):
                raise FileExistsError(self.keyfile)
            st = {"seed": os.urandom(32).hex(), "I": os.urandom(16).hex(),
                  "h0": h0, "h1": h1, "next_epoch": 0}
            _save_state(self.keyfile, st)
        with open(self.keyfile) as f:
            st = json.load(f)
        self._seed = bytes.fromhex(st["seed"])
        self.h0, self.h1 = st["h0"], st["h1"]
        self._top = LmsTree(bytes.fromhex(st["I"]), _sha(b"top", self._seed), self.h0)
        self.public_key = struct.pack(">I", 2) + self._top.public_key()
        self.epochs_used = []
        self._lock = threading.Lock()
        self._use_prefetch = prefetch
        self._cur = self._open_epoch()
        self._next = None
        self._bg = None
        if prefetch:
            self._prefetch()

    def _reserve_epoch(self):
        # the lock makes two processes on the same key file get different
        # epochs; replicas on other machines get their own slice instead
        # (split_keyfile), since file locks across machines are unreliable
        with open(self.keyfile + ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with open(self.keyfile) as f:
                st = json.load(f)
            e = st["next_epoch"]
            if e >= st.get("end_epoch", 1 << self.h0):
                raise RuntimeError("all epochs in this key file are used")
            st["next_epoch"] = e + 1
            _save_state(self.keyfile, st)   # durable before the epoch is used
        return e

    def _open_epoch(self):
        e = self._reserve_epoch()
        tree = LmsTree(_sha(b"I1", self._seed, struct.pack(">I", e))[:16],
                       _sha(b"seed1", self._seed, struct.pack(">I", e)), self.h1)
        # top-level leaf e signs this epoch's public key; leaf e is used once
        # because e was reserved durably above
        self._top.next = e
        cert = self._top.sign(tree.public_key())
        self.epochs_used.append(e)
        return tree, cert

    def _prefetch(self):
        def work():
            self._next = self._open_epoch()
        self._bg = threading.Thread(target=work, daemon=True)
        self._bg.start()

    def sign(self, msg):
        with self._lock:
            tree, cert = self._cur
            if tree.exhausted():
                if self._use_prefetch:
                    self._bg.join()
                    self._cur, self._next = self._next, None
                    self._prefetch()
                else:
                    self._cur = self._open_epoch()   # build it right here (slow path)
                tree, cert = self._cur
            sig1 = tree.sign(msg)
            return struct.pack(">I", 1) + cert + tree.public_key() + sig1

    def close(self):
        if self._bg is not None:
            self._bg.join()


def split_keyfile(keyfile, out_paths):
    """Give each replica of a log (primary, standbys) its own slice of the
    remaining epochs, so they can sign with the same public key without
    talking to each other, even if two of them believe they are primary.
    The original key file is used up so it cannot be started by mistake."""
    with open(keyfile) as f:
        st = json.load(f)
    lo, hi = st["next_epoch"], st.get("end_epoch", 1 << st["h0"])
    n = len(out_paths)
    if hi - lo < n:
        raise ValueError("not enough epochs left to split")
    step = (hi - lo) // n
    for i, path in enumerate(out_paths):
        part = dict(st, next_epoch=lo + i * step,
                    end_epoch=hi if i == n - 1 else lo + (i + 1) * step)
        if os.path.exists(path):
            raise FileExistsError(path)
        _save_state(os.fspath(path), part)
    st["next_epoch"] = st["end_epoch"] = hi
    _save_state(keyfile, st)


def _save_state(path, st):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    dfd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
