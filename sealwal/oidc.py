"""Just enough OpenID Connect for sealwal: issue and check ID tokens.

The provider here is a stand-in for Google, Entra ID, a national eID broker
and so on. It signs compact JWTs with RS256, which is what almost every real
provider uses today, or with ML-DSA-44 as registered for JOSE in RFC 9964.
sealwal does not need the provider to change anything: RS256 tokens work,
and their evidence is kept valid past the point where RSA can be broken by
sealing a commitment to them in the log in time (see provenance.py).

The nonce trick is the one from OpenPubkey and zkLogin: the client puts
H(vk | t_max | r) into the authentication request, so the signed token
vouches for the client's session key without the provider knowing it.
"""

import base64
import hashlib
import json
import os
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, padding, rsa


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    if isinstance(s, str):
        s = s.encode()
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def nonce_for(vk, t_max, r):
    """OIDC nonce that commits to a session key. r is 32 random bytes and stays
    with the client, so the token alone doesn't reveal which key it vouches for."""
    h = hashlib.sha256(b"sealwal/nonce/v1" + len(vk).to_bytes(4, "big") + vk
                       + t_max.to_bytes(8, "big") + r).digest()
    return b64u(h)


class TokenError(Exception):
    pass


class Provider:
    """alg: "RS256" or "ML-DSA-44"."""

    def __init__(self, iss="https://idp.example", alg="RS256", kid=None):
        self.iss = iss
        self.alg = alg
        self.kid = kid or os.urandom(6).hex()
        if alg == "RS256":
            self._sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = self._sk.public_key().public_bytes(serialization.Encoding.DER,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo)
        elif alg == "ML-DSA-44":
            self._sk = mldsa.MLDSA44PrivateKey.generate()
            pub = self._sk.public_key().public_bytes_raw()
        else:
            raise ValueError(alg)
        self.jwk = {"kid": self.kid, "alg": alg, "key": pub}

    def issue(self, sub, aud, nonce, lifetime=3600, now=None, extra=None):
        now = int(now if now is not None else time.time())
        claims = {"iss": self.iss, "aud": aud, "sub": sub, "nonce": nonce,
                  "iat": now, "exp": now + lifetime}
        if extra:
            claims.update(extra)
        head = b64u(json.dumps({"alg": self.alg, "kid": self.kid, "typ": "JWT"},
                               separators=(",", ":")).encode())
        body = b64u(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{head}.{body}".encode()
        if self.alg == "RS256":
            sig = self._sk.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            sig = self._sk.sign(signing_input)
        return f"{head}.{body}.{b64u(sig)}"


def _check_sig(alg, key, signing_input, sig):
    try:
        if alg == "RS256":
            pub = serialization.load_der_public_key(key)
            pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "ML-DSA-44":
            mldsa.MLDSA44PublicKey.from_public_bytes(key).verify(sig, signing_input)
        else:
            return False
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_token(jwt, jwks, aud=None, now=None, leeway=60):
    """Check signature and the standard claims; return (header, claims).
    jwks: {kid: {"alg":..., "key": bytes}}. now=None skips the expiry check
    (used when re-checking an old token whose time was proven another way)."""
    try:
        head_b, body_b, sig_b = jwt.split(".")
        head = json.loads(unb64u(head_b))
        claims = json.loads(unb64u(body_b))
        sig = unb64u(sig_b)
    except (ValueError, json.JSONDecodeError) as e:
        raise TokenError(f"malformed token: {e}")
    jwk = jwks.get(head.get("kid"))
    if jwk is None or jwk["alg"] != head.get("alg"):
        raise TokenError("unknown signing key")
    if not _check_sig(jwk["alg"], jwk["key"], f"{head_b}.{body_b}".encode(), sig):
        raise TokenError("bad token signature")
    for c in ("iss", "aud", "sub", "nonce", "iat", "exp"):
        if c not in claims:
            raise TokenError(f"missing claim {c}")
    if aud is not None and claims["aud"] != aud:
        raise TokenError("wrong audience")
    if now is not None and not claims["iat"] - leeway <= now <= claims["exp"] + leeway:
        raise TokenError("token expired or not yet valid")
    return head, claims


def is_post_quantum(alg):
    return alg == "ML-DSA-44"
