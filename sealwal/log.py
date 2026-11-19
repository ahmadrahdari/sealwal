"""Writer side: an append-only log with sealed group commits.

Commit protocol
---------------
``append()`` only buffers a record in memory. ``commit()`` writes all buffered
records plus one SEAL frame with a single write() call and then flushes the
file (fdatasync by default). A record is committed once its seal is durable;
anything after the last seal is discarded on recovery, exactly like an
uncommitted transaction in a normal write-ahead log.

Signing policies
----------------
sign_every=1   (default) every seal is signed before it is written. Strongest:
               a commit is acknowledged only once it is authenticated. The
               signature sits on the commit critical path.
sign_every=k   only every k-th seal is signed inline; seals in between are
               authenticated by the next signature through the digest chain.
async_sign     seals are written unsigned and a background thread signs the
               newest seal digest whenever it is free, appending a SIG frame.
               Signing is off the critical path; the price is a short
               *authentication window* in which committed-but-unsigned seals
               exist (bounded by roughly one signing time).

A cleanly closed log is always fully signed: ``close()`` signs the last seal
if no signature covers it yet.
"""

from __future__ import annotations

import os
import threading
import time

from . import format as fmt
from . import merkle
from .signers import Signer
from .verify import verify

_SYNC = {
    "fsync": os.fsync,
    "fdatasync": getattr(os, "fdatasync", os.fsync),
    "none": lambda _fd: None,
}


class CorruptLogError(Exception):
    def __init__(self, report):
        super().__init__("; ".join(report.errors))
        self.report = report


class SealedLog:
    """Append-only, tamper-evident log. Thread-safe for concurrent append();
    commit() may be called from any thread (calls are serialised)."""

    def __init__(self, path, fd, signer: Signer, sync: str, sign_every: int, async_sign: bool,
                 track_auth_lag: bool = False):
        if sync not in _SYNC:
            raise ValueError(f"sync must be one of {sorted(_SYNC)}")
        self.path = os.fspath(path)
        self.signer = signer
        self._fd = fd
        self._sync = _SYNC[sync]
        self._sign_every = sign_every
        self._async = async_sign and signer.alg != "none"

        self._lock = threading.Lock()  # protects pending buffer and counters
        self._commit_lock = threading.Lock()  # serialises commits
        self._io_lock = threading.Lock()  # serialises write() calls

        self._pending_frames: list[bytes] = []
        self._pending_leaves: list[bytes] = []
        self._next_lsn = 1
        self._next_seal = 0
        self._prev_digest = b""
        self._committed_lsn = 0
        self._signed_seal = -1
        self._last_seal_digest: bytes | None = None
        self._closed = False
        # Optional measurement: seconds from a seal becoming durable until a
        # signature covering it is written (the authentication window).
        self.auth_lag: list[float] | None = [] if track_auth_lag else None
        self._commit_t: dict[int, float] = {}

        # asynchronous signer state
        self._sig_cv = threading.Condition()
        self._to_sign: tuple[int, bytes] | None = None
        self._stop_signer = False
        self._signer_error: BaseException | None = None
        self._signer_thread = None
        if self._async:
            self._signer_thread = threading.Thread(target=self._signer_loop, name="sealwal-signer", daemon=True)
            self._signer_thread.start()

    # ------------------------------------------------------------------ open

    @classmethod
    def create(cls, path, signer: Signer, *, sync="fdatasync", sign_every=1, async_sign=False,
               track_auth_lag=False) -> "SealedLog":
        """Create a new, empty log file (fails if it already exists)."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o644)
        header = fmt.Header(signer.alg_id, signer.public_bytes)
        _write_all(fd, header.encode())
        _SYNC[sync](fd)
        log = cls(path, fd, signer, sync, sign_every, async_sign, track_auth_lag)
        log._prev_digest = header.genesis_digest()
        return log

    @classmethod
    def open(cls, path, signer: Signer, *, sync="fdatasync", sign_every=1, async_sign=False,
               track_auth_lag=False) -> "SealedLog":
        """Open an existing log for appending, after crash recovery.

        The log is verified against ``signer``'s public key. Uncommitted
        records and torn bytes after the last seal are truncated away. If the
        tail contains committed but unsigned seals (a crash inside the
        authentication window), they are signed now: like any WAL, recovery
        trusts the local disk for that short window.
        """
        seals = []
        rep = verify(path, signer.public_bytes if signer.alg != "none" else None, _seals_out=seals)
        if not rep.ok:
            raise CorruptLogError(rep)
        os.truncate(path, rep.commit_end_offset)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        log = cls(path, fd, signer, sync, sign_every, async_sign, track_auth_lag)
        hdr = fmt.Header(signer.alg_id, signer.public_bytes)
        log._prev_digest = seals[-1].digest if seals else hdr.genesis_digest()
        log._last_seal_digest = seals[-1].digest if seals else None
        log._next_seal = len(seals)
        log._committed_lsn = rep.committed_lsn
        log._next_lsn = rep.committed_lsn + 1
        log._signed_seal = len(seals) - 1 - rep.unauthenticated_seals if signer.alg != "none" else len(seals) - 1
        log.recovery_report = rep
        if signer.alg != "none" and log._signed_seal < len(seals) - 1:
            log._sign_tail_now()
        return log

    # ----------------------------------------------------------------- write

    def append(self, payload: bytes) -> int:
        """Buffer one record; returns its LSN. Not durable until commit()."""
        with self._lock:
            if self._closed:
                raise ValueError("log is closed")
            lsn = self._next_lsn
            self._next_lsn += 1
            self._pending_frames.append(fmt.encode_data(lsn, payload))
            self._pending_leaves.append(merkle.leaf_hash(lsn, payload))
            return lsn

    def pending(self) -> int:
        with self._lock:
            return len(self._pending_frames)

    def commit(self) -> fmt.SealRecord | None:
        """Seal and durably write all buffered records. Returns the seal, or
        None if nothing was pending."""
        self._raise_signer_error()
        with self._commit_lock:
            with self._lock:
                if not self._pending_frames:
                    return None
                frames, leaves = self._pending_frames, self._pending_leaves
                self._pending_frames, self._pending_leaves = [], []
                last = self._next_lsn - 1
                first = last - len(leaves) + 1
                seal_no = self._next_seal
                self._next_seal += 1
                prev = self._prev_digest
            root = merkle.root(leaves)
            seal = fmt.SealRecord(seal_no, first, last, root, prev)
            digest = seal.digest()
            sign_inline = (
                self.signer.alg != "none"
                and not self._async
                and self._sign_every > 0
                and (seal_no + 1) % self._sign_every == 0
            )
            if sign_inline:
                seal = fmt.SealRecord(seal_no, first, last, root, prev, self.signer.sign(fmt.signed_message(digest)))
            buf = b"".join(frames) + fmt.encode_seal(seal)
            with self._io_lock:
                _write_all(self._fd, buf)
            self._sync(self._fd)
            with self._lock:
                self._prev_digest = digest
                self._last_seal_digest = digest
                self._committed_lsn = last
                if sign_inline:
                    self._signed_seal = seal_no
                if self.auth_lag is not None:
                    if self.signer.alg != "none" and not sign_inline:
                        self._commit_t[seal_no] = time.perf_counter()
                    elif sign_inline:
                        self._record_auth(seal_no)
            if self._async:
                with self._sig_cv:
                    self._to_sign = (seal_no, digest)
                    self._sig_cv.notify()
            return seal

    # --------------------------------------------------------------- signing

    def _signer_loop(self) -> None:
        try:
            while True:
                with self._sig_cv:
                    while self._to_sign is None and not self._stop_signer:
                        self._sig_cv.wait()
                    if self._to_sign is None:
                        return
                    seal_no, digest = self._to_sign
                    self._to_sign = None  # newer seals coalesce: sign only the newest
                sig = self.signer.sign(fmt.signed_message(digest))
                with self._io_lock:
                    _write_all(self._fd, fmt.encode_sig(seal_no, sig))
                # No flush here: the next commit's flush makes it durable.
                with self._lock:
                    self._record_auth(seal_no)
                    self._signed_seal = max(self._signed_seal, seal_no)
        except BaseException as e:  # surfaced on the next commit()/close()
            self._signer_error = e

    def _record_auth(self, seal_no: int) -> None:
        """Called with self._lock held when seals <= seal_no become signed."""
        if self.auth_lag is None:
            return
        now = time.perf_counter()
        for j in [j for j in self._commit_t if j <= seal_no]:
            self.auth_lag.append(now - self._commit_t.pop(j))

    def _raise_signer_error(self) -> None:
        if self._signer_error is not None:
            raise RuntimeError("background signer failed") from self._signer_error

    def _sign_tail_now(self) -> None:
        with self._lock:
            seal_no = self._next_seal - 1
            digest = self._last_seal_digest
            if seal_no < 0 or self._signed_seal >= seal_no:
                return
        sig = self.signer.sign(fmt.signed_message(digest))
        with self._io_lock:
            _write_all(self._fd, fmt.encode_sig(seal_no, sig))
        self._sync(self._fd)
        with self._lock:
            self._record_auth(seal_no)
            self._signed_seal = seal_no

    # ----------------------------------------------------------------- state

    @property
    def committed_lsn(self) -> int:
        """Highest LSN whose seal is durable."""
        with self._lock:
            return self._committed_lsn

    @property
    def signed_seal(self) -> int:
        """Highest seal number covered by a signature written to the log."""
        with self._lock:
            return self._signed_seal

    def anchor(self) -> tuple[int, bytes] | None:
        """(seal_no, digest) of the newest durable seal. Store it somewhere the
        log's storage cannot modify to detect rollback later."""
        with self._lock:
            if self._last_seal_digest is None:
                return None
            return self._next_seal - 1, self._last_seal_digest

    def close(self, commit_pending: bool = True) -> None:
        """Optionally commit buffered records, sign the tail, flush, close."""
        if self._closed:
            return
        if commit_pending:
            self.commit()
        if self._signer_thread is not None:
            with self._sig_cv:
                self._stop_signer = True
                self._sig_cv.notify()
            self._signer_thread.join()
            self._raise_signer_error()
        if self.signer.alg != "none":
            self._sign_tail_now()
        self._sync(self._fd)
        with self._lock:
            self._closed = True
        os.close(self._fd)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class GroupCommitter:
    """Classic group commit on top of SealedLog.

    Client threads call ``submit(payload)``, which returns once the record is
    durable. A single committer thread seals whatever has accumulated while
    the previous flush was in progress, so the cost of each flush (and each
    signature) is shared by all records in the batch.
    """

    def __init__(self, log: SealedLog):
        self.log = log
        self._cv = threading.Condition()
        self._durable_lsn = log.committed_lsn
        self._stop = False
        self._error: BaseException | None = None
        self.batches: list[int] = []  # batch sizes, for measurements
        self._thread = threading.Thread(target=self._run, name="sealwal-committer", daemon=True)
        self._thread.start()

    def submit(self, payload: bytes) -> int:
        lsn = self.log.append(payload)
        with self._cv:
            self._cv.notify_all()
            while self._durable_lsn < lsn and self._error is None:
                self._cv.wait()
            if self._error is not None:
                raise RuntimeError("group commit failed") from self._error
        return lsn

    def _run(self) -> None:
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
                    self._error = e
                    self._cv.notify_all()
                return
            if seal is not None:
                with self._cv:
                    self.batches.append(seal.last_lsn - seal.first_lsn + 1)
                    self._durable_lsn = seal.last_lsn
                    self._cv.notify_all()

    def close(self) -> None:
        with self._cv:
            self._stop = True
            self._cv.notify_all()
        self._thread.join()


def _write_all(fd: int, buf: bytes) -> None:
    view = memoryview(buf)
    while view:
        n = os.write(fd, view)
        view = view[n:]
