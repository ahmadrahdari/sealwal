"""Subject key store on SQLite.

One 32-byte key per data subject (an OIDC identity iss/aud/sub). Everything
private in the log is derived from it: the salts of the identity and token
commitments and the AES-GCM key for payloads. Deleting the key is the
erasure; nothing in the log has to change.

The identity itself is not stored, only handle = HMAC(master, iss|aud|sub),
so a copy of this file doesn't list who the users are. Sessions map to
handles so a record (which only names its session) can be decrypted.

Erasure has to actually remove the bytes. SQLite keeps deleted content in
free pages and in the -wal file unless told otherwise, so we run with
secure_delete=ON and truncate the WAL after every shred. Backups of this
file need the same retention policy as the keys themselves (the log's
backups don't, which is the point).
"""

import hashlib
import hmac
import os
import sqlite3
import threading


class Erased(Exception):
    """The subject's key is gone; its records can't be opened anymore."""


def handle_of(master, iss, aud, sub):
    msg = b"\x00".join(x.encode() for x in (iss, aud, sub))
    return hmac.new(master, b"sealwal/handle|" + msg, hashlib.sha256).digest()


class KeyStore:
    def __init__(self, path, master=None, durable=True):
        self.path = os.fspath(path)
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        db = self._db
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA secure_delete=ON")
        db.execute(f"PRAGMA synchronous={'FULL' if durable else 'OFF'}")
        db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB)")
        db.execute("CREATE TABLE IF NOT EXISTS subjects (h BLOB PRIMARY KEY, key BLOB NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS sessions (sid BLOB PRIMARY KEY, h BLOB NOT NULL)")
        db.execute("CREATE INDEX IF NOT EXISTS sessions_h ON sessions(h)")
        row = db.execute("SELECT v FROM meta WHERE k='master'").fetchone()
        if row is None:
            self.master = master or os.urandom(32)
            db.execute("INSERT INTO meta VALUES ('master', ?)", (self.master,))
        else:
            self.master = row[0]
        self._cache = {}      # sid -> key, filled on first use

    def subject(self, iss, aud, sub, create=True):
        """-> (handle, key). Creates the key on first login."""
        h = handle_of(self.master, iss, aud, sub)
        with self._lock:
            row = self._db.execute("SELECT key FROM subjects WHERE h=?", (h,)).fetchone()
            if row is not None:
                return h, row[0]
            if not create:
                raise Erased("no key for this subject")
            key = os.urandom(32)
            self._db.execute("INSERT INTO subjects VALUES (?, ?)", (h, key))
            return h, key

    def add_session(self, sid, h):
        with self._lock:
            self._db.execute("INSERT INTO sessions VALUES (?, ?)", (sid, h))

    def key_for_session(self, sid):
        k = self._cache.get(sid)
        if k is not None:
            return k
        with self._lock:
            row = self._db.execute("SELECT s.key FROM sessions x JOIN subjects s ON s.h = x.h "
                                   "WHERE x.sid=?", (sid,)).fetchone()
        if row is None:
            raise Erased("session belongs to an erased subject (or never existed)")
        self._cache[sid] = row[0]
        return row[0]

    def handle_for_session(self, sid):
        with self._lock:
            row = self._db.execute("SELECT h FROM sessions WHERE sid=?", (sid,)).fetchone()
        if row is None:
            raise Erased("unknown session")
        return row[0]

    def shred(self, h):
        """Erase one subject: its key and the session -> subject links.
        Returns the number of sessions that became unreadable."""
        with self._lock:
            sids = [r[0] for r in self._db.execute("SELECT sid FROM sessions WHERE h=?", (h,))]
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute("DELETE FROM sessions WHERE h=?", (h,))
            self._db.execute("DELETE FROM subjects WHERE h=?", (h,))
            self._db.execute("COMMIT")
            # the old pages sit in the -wal file until a checkpoint copies the
            # (zeroed) pages back; truncate it so no copy of the key survives
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            for s in sids:
                self._cache.pop(s, None)
        return len(sids)

    def bulk_load(self, n, batch=50_000):
        """Fill with n synthetic subjects (benchmarks)."""
        with self._lock:
            done = 0
            while done < n:
                k = min(batch, n - done)
                self._db.execute("BEGIN")
                self._db.executemany("INSERT INTO subjects VALUES (?, ?)",
                                     ((os.urandom(32), os.urandom(32)) for _ in range(k)))
                self._db.execute("COMMIT")
                done += k

    def count(self):
        with self._lock:
            return self._db.execute("SELECT count(*) FROM subjects").fetchone()[0]

    def close(self):
        with self._lock:
            self._db.close()
