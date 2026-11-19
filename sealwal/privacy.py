"""Private and erasable records.

A record can belong to a data subject (a user, a patient, a tenant...). Each
subject has a 32-byte key in a KeyStore that lives next to the log but is
*mutable*. For a record of subject s at position lsn:

    salt = HMAC(k_s, "salt" | lsn)
    c    = H("sealwal/c/v1" | salt | payload)       # goes into the tree
    body = AES-256-GCM(HMAC(k_s, "enc"), nonce=lsn, payload, aad=lsn|s)

The Merkle leaf is built from c, never from the payload. So:

  - inclusion proofs only expose salted commitments of neighbouring records,
    so low-entropy neighbours (balances, codes) can't be brute-forced;
  - the structure (and append-only property) can be audited with no keys;
  - shredding k_s makes every record of s unreadable for good, while the
    log, its signatures and all proofs for other records keep verifying.

Records with subject 0 are public: zero salt, plaintext body.
"""

import hashlib
import hmac
import json
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ZERO_SALT = bytes(32)


def commit(salt, payload):
    return hashlib.sha256(b"sealwal/c/v1" + salt + payload).digest()


class Erased(Exception):
    """The subject's key is gone: the record can't be opened any more."""


class KeyStore:
    def __init__(self, path, create=False):
        self.path = os.fspath(path)
        if create and not os.path.exists(self.path):
            self._keys = {}
            self._save()
        with open(self.path) as f:
            self._keys = {int(k): bytes.fromhex(v) for k, v in json.load(f).items()}
        self._cache = {}

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({str(k): v.hex() for k, v in self._keys.items()}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def add_subject(self, subject):
        if subject <= 0:
            raise ValueError("subject ids start at 1 (0 means public)")
        if subject not in self._keys:
            self._keys[subject] = os.urandom(32)
            self._save()
        return subject

    def has(self, subject):
        return subject in self._keys

    def shred(self, subject):
        """Right to erasure. Note this only removes the key from this file;
        backups of the key store must be handled too."""
        self._keys.pop(subject, None)
        self._cache.pop(subject, None)
        self._save()

    def _derived(self, subject):
        if subject not in self._cache:
            k = self._keys.get(subject)
            if k is None:
                raise Erased(subject)
            enc = hmac.new(k, b"enc", hashlib.sha256).digest()
            self._cache[subject] = (k, AESGCM(enc))
        return self._cache[subject]

    def salt(self, subject, lsn):
        k, _ = self._derived(subject)
        return hmac.new(k, b"salt" + struct.pack(">Q", lsn), hashlib.sha256).digest()

    def seal(self, subject, lsn, payload):
        """-> (salt, ciphertext)"""
        _, aead = self._derived(subject)
        nonce = struct.pack(">IQ", 0, lsn)
        aad = struct.pack(">QI", lsn, subject)
        return self.salt(subject, lsn), aead.encrypt(nonce, payload, aad)

    def open(self, subject, lsn, body):
        """-> (salt, payload). Raises Erased, or ValueError if tampered."""
        _, aead = self._derived(subject)
        nonce = struct.pack(">IQ", 0, lsn)
        aad = struct.pack(">QI", lsn, subject)
        try:
            payload = aead.decrypt(nonce, body, aad)
        except InvalidTag:
            raise ValueError(f"LSN {lsn}: ciphertext was modified")
        return self.salt(subject, lsn), payload
