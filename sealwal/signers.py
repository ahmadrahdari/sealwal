"""Signature schemes used to seal log batches.

Every scheme exposes the same tiny interface so the log code never needs to
know which algorithm is in use:

    signer = make_signer("ml-dsa-65")         # fresh key
    sig = signer.sign(message)
    ok = verify_signature("ml-dsa-65", signer.public_bytes, sig, message)

Algorithms
----------
none        No signature. Seals still carry a Merkle root and a hash chain, so
            accidental corruption is detected, but anyone who can write the
            file can forge a consistent log. Used as the performance baseline.
ed25519     Classical signature (64-byte signatures). Not quantum-safe.
ml-dsa-44   FIPS 204 lattice signature, NIST security category 2.
ml-dsa-65   FIPS 204, category 3 (the usual default).
ml-dsa-87   FIPS 204, category 5.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

# Stable numeric ids, written into the log header.
ALG_IDS = {"none": 0, "ed25519": 1, "ml-dsa-44": 2, "ml-dsa-65": 3, "ml-dsa-87": 4}
ALG_NAMES = {v: k for k, v in ALG_IDS.items()}

_MLDSA = {
    "ml-dsa-44": (mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey),
    "ml-dsa-65": (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey),
    "ml-dsa-87": (mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey),
}


@dataclass
class Signer:
    """A private signing key plus its algorithm name and public key bytes."""

    alg: str
    public_bytes: bytes
    private_bytes: bytes
    _sign: Callable[[bytes], bytes]

    @property
    def alg_id(self) -> int:
        return ALG_IDS[self.alg]

    def sign(self, message: bytes) -> bytes:
        return self._sign(message)


def make_signer(alg: str, private_bytes: bytes | None = None) -> Signer:
    """Create a signer. Pass ``private_bytes`` to load an existing key
    (32-byte seed for both Ed25519 and ML-DSA), or omit it to generate one."""
    if alg == "none":
        return Signer("none", b"", b"", lambda _m: b"")
    if alg == "ed25519":
        key = (
            ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
            if private_bytes
            else ed25519.Ed25519PrivateKey.generate()
        )
        return Signer(alg, key.public_key().public_bytes_raw(), key.private_bytes_raw(), key.sign)
    if alg in _MLDSA:
        priv_cls, _ = _MLDSA[alg]
        key = priv_cls.from_seed_bytes(private_bytes) if private_bytes else priv_cls.generate()
        return Signer(alg, key.public_key().public_bytes_raw(), key.private_bytes_raw(), key.sign)
    raise ValueError(f"unknown signature algorithm: {alg!r} (choose from {sorted(ALG_IDS)})")


def verify_signature(alg: str, public_bytes: bytes, signature: bytes, message: bytes) -> bool:
    """Return True iff ``signature`` is valid for ``message`` under the key."""
    if alg == "none":
        return signature == b""
    try:
        if alg == "ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, message)
            return True
        if alg in _MLDSA:
            _, pub_cls = _MLDSA[alg]
            pub_cls.from_public_bytes(public_bytes).verify(signature, message)
            return True
    except (InvalidSignature, ValueError):
        return False
    raise ValueError(f"unknown signature algorithm: {alg!r}")
