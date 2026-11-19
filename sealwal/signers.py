"""Signature schemes behind one small interface.

    s = make_signer("ml-dsa-65")
    sig = s.sign(msg)
    verify_signature("ml-dsa-65", s.public_bytes, sig, msg)

none        no signature. Seals still carry the Merkle root and hash chain,
            so corruption is caught, forgery isn't. Baseline only.
ed25519     classical, not quantum-safe
ml-dsa-44/65/87          FIPS 204 lattice signatures
hybrid-ed25519-ml-dsa-65 both, both must verify (migration setting)
lms-hss     RFC 8554 hash-based, two levels, state kept per recovery epoch
            (see lms.py). Here private_bytes is the path of the key file.
"""

import os
import tempfile
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

HYBRID = "hybrid-ed25519-ml-dsa-65"
ALG_IDS = {"none": 0, "ed25519": 1, "ml-dsa-44": 2, "ml-dsa-65": 3, "ml-dsa-87": 4,
           HYBRID: 5, "lms-hss": 6}
ALG_NAMES = {v: k for k, v in ALG_IDS.items()}

_MLDSA = {
    "ml-dsa-44": (mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey),
    "ml-dsa-65": (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey),
    "ml-dsa-87": (mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey),
}


@dataclass
class Signer:
    alg: str
    public_bytes: bytes
    private_bytes: bytes
    _sign: Callable

    @property
    def alg_id(self):
        return ALG_IDS[self.alg]

    def sign(self, msg):
        return self._sign(msg)


def make_signer(alg, private_bytes=None):
    """Fresh key, or load one (private_bytes as stored in Signer.private_bytes)."""
    if alg == "none":
        return Signer("none", b"", b"", lambda m: b"")
    if alg == "ed25519":
        k = (ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes) if private_bytes
             else ed25519.Ed25519PrivateKey.generate())
        return Signer(alg, k.public_key().public_bytes_raw(), k.private_bytes_raw(), k.sign)
    if alg in _MLDSA:
        cls = _MLDSA[alg][0]
        k = cls.from_seed_bytes(private_bytes) if private_bytes else cls.generate()
        return Signer(alg, k.public_key().public_bytes_raw(), k.private_bytes_raw(), k.sign)
    if alg == HYBRID:
        ed = make_signer("ed25519", private_bytes[:32] if private_bytes else None)
        ml = make_signer("ml-dsa-65", private_bytes[32:] if private_bytes else None)
        return Signer(alg, ed.public_bytes + ml.public_bytes, ed.private_bytes + ml.private_bytes,
                      lambda m: ed.sign(m) + ml.sign(m))
    if alg == "lms-hss":
        from . import lms
        if private_bytes:
            key = lms.EpochHss(private_bytes.decode())
        else:
            path = os.path.join(tempfile.mkdtemp(prefix="sealwal-"), "lms-key.json")
            key = lms.EpochHss(path, create=True)
        return Signer(alg, key.public_key, key.keyfile.encode(), key.sign)
    raise ValueError(f"unknown algorithm {alg!r}, pick one of {sorted(ALG_IDS)}")


def verify_signature(alg, pub, sig, msg):
    if alg == "none":
        return sig == b""
    if alg == HYBRID:
        return (verify_signature("ed25519", pub[:32], sig[:64], msg)
                and verify_signature("ml-dsa-65", pub[32:], sig[64:], msg))
    if alg == "lms-hss":
        from . import lms
        return lms.hss_verify(pub, msg, sig)
    try:
        if alg == "ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        elif alg in _MLDSA:
            _MLDSA[alg][1].from_public_bytes(pub).verify(sig, msg)
        else:
            raise ValueError(f"unknown algorithm {alg!r}")
    except (InvalidSignature, ValueError):
        return False
    return True
