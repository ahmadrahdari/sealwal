"""Log writer.

append() only buffers. commit() writes the buffered records plus one SEAL in a
single write() and flushes. A record counts as committed once its seal is on
disk; anything after the last seal is dropped on recovery, like an uncommitted
transaction in a normal WAL.

Each seal carries the root of the Merkle tree over *all* records so far, so a
signature over one seal covers the whole log up to that point.

Records can be public (subject 0) or belong to a data subject; private ones
are encrypted and committed with a salt from the subject's key, so shredding
that key erases them without breaking the log (see privacy.py).

Signing modes:
  sign_every=1        sign every seal before writing it (default)
  sign_every=k        sign every k-th seal inline
  async_sign=True     a background thread signs the newest seal and appends a
                      SIG frame; commits don't wait for it
  max_unsigned=K      (async only) commit() blocks while more than K committed
                      seals are unsigned, which bounds the auth window

Replication: with sink=QuorumSink(...) (replica.py) every write also goes
to the log nodes and a commit returns once a quorum has it on disk. The
local file is then just the writer's copy and doesn't need its own flush.
keep_tree=True keeps every leaf and subtree hash in memory for checkpoints
and receipts (merkle.Tree).
"""

import os
import threading
import time

from . import format as fmt
from . import merkle
from .privacy import ZERO_SALT, commit
from .verify import verify

_SYNC = {
    "fsync": os.fsync,
    "fdatasync": getattr(os, "fdatasync", os.fsync),
    "none": lambda fd: None,
}


def _flush_fn(sync):
    # "emulate:25" = pretend each flush takes 25 us (busy wait, no fsync).
    # The benchmarks use it to model fast remote log services.
    if sync.startswith("emulate:"):
        delay = float(sync.split(":", 1)[1]) / 1e6

        def spin(fd):
            end = time.perf_counter() + delay
            while time.perf_counter() < end:
                pass
        return spin
    if sync not in _SYNC:
        raise ValueError(f"sync must be one of {sorted(_SYNC)} or emulate:<us>")
    return _SYNC[sync]


class CorruptLogError(Exception):
    def __init__(self, report):
        super().__init__("; ".join(report.errors))
        self.report = report


class SealedLog:
    def __init__(self, path, fd, signer, sync="fdatasync", sign_every=1,
                 async_sign=False, max_unsigned=None, track_auth_lag=False, keys=None,
                 sink=None, keep_tree=False, offset=0):
        self.path = os.fspath(path)
        self.signer = signer
        self.keys = keys
        self._fd = fd
        self._sync = _flush_fn(sync)
        self._sink = sink
        self._off = offset                    # bytes written so far (for the sink)
        self.tree = merkle.Tree() if keep_tree else None
        self.signed_head = None               # (SealRecord, signature) of the newest signed seal
        self._recent = {}                     # seal_no -> SealRecord, for the async signer
        self._sign_every = sign_every
        self._async = async_sign and signer.alg != "none"
        self._max_unsigned = max_unsigned if self._async else None

        self._lock = threading.Lock()         # buffer + counters
        self._signed = threading.Condition(self._lock)
        self._commit_lock = threading.Lock()  # one commit at a time
        self._io_lock = threading.Lock()      # one write() at a time

        self._frames = []
        self._leaves = []
        self._tree = merkle.Frontier()        # committed records only
        self._next_lsn = 1
        self._next_seal = 0
        self._prev = b""
        self._last_digest = None
        self._committed_lsn = 0
        self._signed_seal = -1
        self._closed = False

        # benchmarks: time from a seal hitting disk until something signs it
        self.auth_lag = [] if track_auth_lag else None
        self._commit_t = {}

        self._sig_cv = threading.Condition()
        self._to_sign = None
        self._stop = False
        self._signer_err = None
        self._signer_thread = None
        if self._async:
            self._signer_thread = threading.Thread(target=self._signer_loop, daemon=True)
            self._signer_thread.start()

    @classmethod
    def create(cls, path, signer, **opts):
        """New empty log. Fails if the file exists."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o644)
        hdr = fmt.Header(signer.alg_id, signer.public_bytes)
        raw = hdr.encode()
        _write_all(fd, raw)
        _flush_fn(opts.get("sync", "fdatasync"))(fd)
        log = cls(path, fd, signer, offset=len(raw), **opts)
        if log._sink is not None:
            log._sink.wait(log._sink.send(0, raw))
        log._prev = hdr.genesis_digest()
        return log

    @classmethod
    def open(cls, path, signer, **opts):
        """Reopen after a crash or a clean shutdown.

        The file is verified against the signer's key first. Torn bytes and
        records after the last seal get truncated. Seals that were committed
        but never signed (crash inside the auth window) are signed now, i.e.
        recovery trusts the local disk for that window, same as any WAL.
        """
        state = {}
        key = signer.public_bytes if signer.alg != "none" else None
        rep = verify(path, key, _state_out=state)
        if not rep.ok:
            raise CorruptLogError(rep)
        os.truncate(path, rep.commit_end_offset)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        log = cls(path, fd, signer, offset=rep.commit_end_offset, **opts)
        seals = state["seals"]
        log._tree = state["tree"]
        if seals:
            log._prev = log._last_digest = seals[-1].digest
        else:
            log._prev = fmt.Header(signer.alg_id, signer.public_bytes).genesis_digest()
        log._next_seal = len(seals)
        log._committed_lsn = rep.committed_lsn
        log._next_lsn = rep.committed_lsn + 1
        log._signed_seal = len(seals) - 1
        if signer.alg != "none":
            log._signed_seal -= rep.unauthenticated_seals
        log.recovery_report = rep
        if signer.alg != "none" and log._signed_seal < len(seals) - 1:
            log._sign_tail()
        return log

    def append(self, payload, subject=0):
        """Buffer a record. subject > 0 makes it private to that data subject
        (needs keys=KeyStore(...) when opening the log)."""
        if subject and self.keys is None:
            raise ValueError("private records need a KeyStore (keys=...)")
        with self._lock:
            if self._closed:
                raise ValueError("log is closed")
            lsn = self._next_lsn
            self._next_lsn += 1
            if subject:
                salt, body = self.keys.seal(subject, lsn, payload)
            else:
                salt, body = ZERO_SALT, payload
            c = commit(salt, payload)
            self._frames.append(fmt.encode_data(lsn, subject, c, body))
            self._leaves.append(merkle.leaf_hash(lsn, c))
            return lsn

    def pending(self):
        with self._lock:
            return len(self._frames)

    def commit(self):
        """Seal and flush everything buffered. Returns the SealRecord, or None
        if there was nothing to commit."""
        self._check_signer()
        with self._commit_lock:
            with self._lock:
                if not self._frames:
                    return None
                frames, leaves = self._frames, self._leaves
                self._frames, self._leaves = [], []
                last = self._next_lsn - 1
                first = last - len(leaves) + 1
                seal_no = self._next_seal
                self._next_seal += 1
                prev = self._prev

            # only the committing thread touches the tree
            for leaf in leaves:
                self._tree.append(leaf)
                if self.tree is not None:
                    self.tree.append(leaf)
            seal = fmt.SealRecord(seal_no, first, last, self._tree.root(), prev)
            digest = seal.digest()

            inline = (self.signer.alg != "none" and not self._async
                      and self._sign_every > 0 and (seal_no + 1) % self._sign_every == 0)
            if inline:
                sig = self.signer.sign(fmt.signed_message(digest))
                seal = fmt.SealRecord(seal_no, first, last, seal.root, prev, sig)

            end = self._write(b"".join(frames) + fmt.encode_seal(seal))
            self._sync(self._fd)
            if self._sink is not None:
                self._sink.wait(end)

            with self._lock:
                self._prev = self._last_digest = digest
                self._committed_lsn = last
                if inline:
                    self._signed_seal = seal_no
                    self.signed_head = (seal, seal.signature)
                    self._note_signed(seal_no)
                elif self._async:
                    self._recent[seal_no] = seal
                    if len(self._recent) > 4096:
                        self._recent.pop(min(self._recent))
                elif self.auth_lag is not None and self.signer.alg != "none":
                    self._commit_t[seal_no] = time.perf_counter()

            if self._async:
                with self._sig_cv:
                    self._to_sign = (seal_no, digest)
                    self._sig_cv.notify()
                if self._max_unsigned is not None:
                    with self._signed:
                        while (seal_no - self._signed_seal > self._max_unsigned
                               and self._signer_err is None):
                            self._signed.wait()
                    self._check_signer()
            return seal

    def _signer_loop(self):
        try:
            while True:
                with self._sig_cv:
                    while self._to_sign is None and not self._stop:
                        self._sig_cv.wait()
                    if self._to_sign is None:
                        return
                    seal_no, digest = self._to_sign
                    self._to_sign = None   # fell behind? only the newest gets signed
                sig = self.signer.sign(fmt.signed_message(digest))
                self._write(fmt.encode_sig(seal_no, sig))
                # not flushed here, the next commit's flush picks it up
                with self._signed:
                    if seal_no > self._signed_seal and seal_no in self._recent:
                        self.signed_head = (self._recent[seal_no], sig)
                    self._signed_seal = max(self._signed_seal, seal_no)
                    self._note_signed(seal_no)
                    self._signed.notify_all()
        except BaseException as e:
            with self._signed:
                self._signer_err = e
                self._signed.notify_all()

    def _note_signed(self, seal_no):
        # caller holds self._lock
        if self.auth_lag is None:
            return
        now = time.perf_counter()
        for j in [j for j in self._commit_t if j <= seal_no]:
            self.auth_lag.append(now - self._commit_t.pop(j))

    def _check_signer(self):
        if self._signer_err is not None:
            raise RuntimeError("background signer failed") from self._signer_err

    def _sign_tail(self):
        with self._lock:
            seal_no = self._next_seal - 1
            digest = self._last_digest
            if seal_no < 0 or self._signed_seal >= seal_no:
                return
        sig = self.signer.sign(fmt.signed_message(digest))
        end = self._write(fmt.encode_sig(seal_no, sig))
        self._sync(self._fd)
        if self._sink is not None:
            self._sink.wait(end)
        with self._lock:
            if seal_no in self._recent:
                self.signed_head = (self._recent[seal_no], sig)
            self._signed_seal = seal_no
            self._note_signed(seal_no)

    def _write(self, buf):
        """Append to the local copy and queue for the log nodes, in one order."""
        with self._io_lock:
            _write_all(self._fd, buf)
            off = self._off
            self._off += len(buf)
            if self._sink is not None:
                return self._sink.send(off, buf)
            return self._off

    @property
    def committed_lsn(self):
        with self._lock:
            return self._committed_lsn

    @property
    def signed_seal(self):
        with self._lock:
            return self._signed_seal

    def anchor(self):
        """(seal_no, digest) of the newest seal. Keep it somewhere the log's
        storage can't write to; verify(..., anchor=...) then catches rollback."""
        with self._lock:
            if self._last_digest is None:
                return None
            return self._next_seal - 1, self._last_digest

    def close(self, commit_pending=True):
        if self._closed:
            return
        if commit_pending:
            self.commit()
        if self._signer_thread is not None:
            with self._sig_cv:
                self._stop = True
                self._sig_cv.notify()
            self._signer_thread.join()
            self._check_signer()
        if self.signer.alg != "none":
            self._sign_tail()
        self._sync(self._fd)
        with self._lock:
            self._closed = True
        os.close(self._fd)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class GroupCommitter:
    """Group commit: clients call submit(), which returns once the record is
    durable. One committer thread seals whatever piled up during the previous
    flush, so the flush (and the signature) is shared by the whole batch."""

    def __init__(self, log):
        self.log = log
        self.batches = []
        self._cv = threading.Condition()
        self._durable = log.committed_lsn
        self._stop = False
        self._err = None
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def submit(self, payload):
        lsn = self.log.append(payload)
        with self._cv:
            self._cv.notify_all()
            while self._durable < lsn and self._err is None:
                self._cv.wait()
            if self._err is not None:
                raise RuntimeError("group commit failed") from self._err
        return lsn

    def _run(self):
        while True:
            with self._cv:
                while not self.log.pending() and not self._stop:
                    self._cv.wait()
                if self._stop and not self.log.pending():
                    return
            try:
                seal = self.log.commit()
            except BaseException as e:
                with self._cv:
                    self._err = e
                    self._cv.notify_all()
                return
            if seal is not None:
                with self._cv:
                    self.batches.append(seal.last_lsn - seal.first_lsn + 1)
                    self._durable = seal.last_lsn
                    self._cv.notify_all()

    def close(self):
        with self._cv:
            self._stop = True
            self._cv.notify_all()
        self._t.join()


def _write_all(fd, buf):
    view = memoryview(buf)
    while view:
        view = view[os.write(fd, view):]
