"""Write provenance: who wrote which record, provably and privately.

A user signs in with an ordinary OpenID provider. The client makes a fresh
ML-DSA-44 session key and puts nonce = H(vk | t_max | r) into the login, so
the ID token vouches for that key (same idea as OpenPubkey and zkLogin).
The engine checks the token once, writes a BIND record, and from then on
every transaction request is signed with the session key and logged with
its signature. The engine can't attribute a write to someone who didn't
make it, because it never holds a user's session key.

What goes into the log is only commitments, all salted with values derived
from the subject's key (keystore.py):

    BIND  sid | vk | t_max | mode | c_id | c_tok [| anchor_lsn | anchor_sig]
          rho  = HMAC(k_s, "bind" | sid)
          c_id = H("id", rho, iss, aud, sub)
          c_tok = H("tok", rho, jwt, r)
    TXN   sid | ctr | c_m | sig | public part | AES-GCM_{k_s}(m | rho_m | private part)
          c_m = H("m", rho_m, m), sig = Sign(sk_u, H("req", sid, ctr, c_m))

So the log, its replicas, the archive and auditors see random session ids
and commitments, never who the user is. Deleting k_s erases the subject:
the commitments can't be opened anymore and the payloads can't be read,
while every seal, signature and other receipt keeps verifying.

Commit-then-seal. RS256 will fall to a quantum computer, and nobody can
make Google sign differently. What a quantum adversary can't change is
*when* a token existed. c_tok binds the token, the hash-signed seals and the
witness-cosigned checkpoints fix its position in time, so a binding with a
classical token is accepted as evidence iff a checkpoint dated before the
sunset (a policy date before RSA-2048 is breakable) covers it. After the
sunset, new bindings need a post-quantum token (ML-DSA, RFC 9964) or a
continuation: a key the user registered in an earlier, valid binding signs
the new session key. One login before the sunset is enough, forever.
"""

import hashlib
import hmac
import json
import os
import struct
import threading
import time

from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

from . import merkle
from . import oidc


BIND, TXN, WITNESS, ERASE, SYS = 1, 2, 3, 4, 5
CLASSICAL, NATIVE, CONTINUATION = 0, 1, 2
MODE_NAMES = {CLASSICAL: "classical", NATIVE: "native", CONTINUATION: "continuation"}


# ----------------------------------------------------------------- encoding

def pack(*fields):
    out = []
    for f in fields:
        if isinstance(f, int):
            f = f.to_bytes(8, "big")
        elif isinstance(f, str):
            f = f.encode()
        out.append(len(f).to_bytes(4, "big") + f)
    return b"".join(out)


def unpack(buf):
    out, off = [], 0
    while off < len(buf):
        n = int.from_bytes(buf[off:off + 4], "big")
        out.append(bytes(buf[off + 4:off + 4 + n]))
        off += 4 + n
    if off != len(buf):
        raise ValueError("trailing bytes in record")
    return out


def H(tag, *parts):
    return hashlib.sha256(b"sealwal/" + tag.encode() + b"/v1" + pack(*parts)).digest()


def prf(key, label, *parts):
    return hmac.new(key, label.encode() + pack(*parts), hashlib.sha256).digest()


def u64(b):
    return int.from_bytes(b, "big")


def encode_bind(sid, vk, t_max, mode, c_id, c_tok, anchor_lsn=0, anchor_sig=b""):
    return bytes([BIND]) + pack(sid, vk, t_max, mode, c_id, c_tok, anchor_lsn, anchor_sig)


def parse_bind(rec):
    if rec[0] != BIND:
        raise ValueError("not a BIND record")
    sid, vk, t_max, mode, c_id, c_tok, a_lsn, a_sig = unpack(rec[1:])
    return {"sid": sid, "vk": vk, "t_max": u64(t_max), "mode": u64(mode), "c_id": c_id,
            "c_tok": c_tok, "anchor_lsn": u64(a_lsn), "anchor_sig": a_sig}


def encode_txn(sid, ctr, c_m, sig, public, enc):
    return bytes([TXN]) + pack(sid, ctr, c_m, sig, public, enc)


def parse_txn(rec):
    if rec[0] != TXN:
        raise ValueError("not a TXN record")
    sid, ctr, c_m, sig, public, enc = unpack(rec[1:])
    return {"sid": sid, "ctr": u64(ctr), "c_m": c_m, "sig": sig, "public": public, "enc": enc}


def request_digest(sid, ctr, c_m):
    return H("req", sid, ctr, c_m)


def continuation_digest(sid, vk, t_max):
    return H("cont", sid, vk, t_max)


def mldsa_verify(vk, sig, msg):
    try:
        mldsa.MLDSA44PublicKey.from_public_bytes(vk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# ------------------------------------------------- post-quantum envelope

class EngineKem:
    """The engine's ML-KEM-768 key. Clients encrypt the bind request (which
    carries the ID token) to it, so a recorded TLS session with classical
    key exchange gives a future quantum attacker nothing. The provider's own
    TLS can stay classical: the token alone doesn't say which session key
    it vouches for, because r never leaves client and engine."""

    def __init__(self):
        self._sk = mlkem.MLKEM768PrivateKey.generate()
        self.public_bytes = self._sk.public_key().public_bytes_raw()

    def open(self, envelope):
        ct, nonce, box = unpack(envelope)
        key = hashlib.sha256(b"sealwal/env/v1" + self._sk.decapsulate(ct)).digest()
        return key, AESGCM(key).decrypt(nonce, box, b"bind")


def seal_envelope(engine_pub, message):
    ss, ct = mlkem.MLKEM768PublicKey.from_public_bytes(engine_pub).encapsulate()
    key = hashlib.sha256(b"sealwal/env/v1" + ss).digest()
    nonce = os.urandom(12)
    return key, pack(ct, nonce, AESGCM(key).encrypt(nonce, message, b"bind"))


def reply(key, message):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, message, b"reply")


def open_reply(key, box):
    return AESGCM(key).decrypt(box[:12], box[12:], b"reply")


# ------------------------------------------------------------------ client

class Session:
    """Client side of one login. login(provider_fn) where provider_fn(nonce)
    runs the OIDC flow and returns the ID token."""

    def __init__(self, lifetime=3600, anchor_key=None):
        self._sk = mldsa.MLDSA44PrivateKey.generate()
        self.vk = self._sk.public_key().public_bytes_raw()
        self.t_max = int(time.time()) + lifetime
        self.r = os.urandom(32)
        self.anchor_key = anchor_key      # long-term ML-DSA key, optional
        self.anchor_vk = anchor_key.public_key().public_bytes_raw() if anchor_key else b""
        # the nonce also commits to the anchor key, so only the user can register one
        self.nonce = oidc.nonce_for(self.vk + self.anchor_vk, self.t_max, self.r)
        self.jwt = None
        self.sid = self.rho = None
        self.bind_lsn = None
        self.ctr = 0

    def bind_message(self, jwt):
        self.jwt = jwt
        msg = {"jwt": jwt, "vk": self.vk.hex(), "t_max": self.t_max, "r": self.r.hex()}
        if self.anchor_vk:
            msg["anchor_vk"] = self.anchor_vk.hex()
        return json.dumps(msg).encode()

    def continuation_message(self, anchor_lsn, sid_hint):
        """After the sunset: the anchored key signs the new session key."""
        sig = self.anchor_key.sign(continuation_digest(sid_hint, self.vk, self.t_max))
        return json.dumps({"vk": self.vk.hex(), "t_max": self.t_max, "anchor_lsn": anchor_lsn,
                           "sid": sid_hint.hex(), "anchor_sig": sig.hex()}).encode()

    def bound(self, sid, rho, lsn):
        self.sid, self.rho, self.bind_lsn = sid, rho, lsn

    def request(self, m):
        """Sign one transaction request. Returns what the engine needs."""
        self.ctr += 1
        rho_m = os.urandom(32)
        c_m = H("m", rho_m, m)
        sig = self._sk.sign(request_digest(self.sid, self.ctr, c_m))
        return {"sid": self.sid, "ctr": self.ctr, "m": m, "rho_m": rho_m, "c_m": c_m, "sig": sig}


# ------------------------------------------------------------------ engine

class PolicyError(Exception):
    pass


class Engine:
    """The database side. log: a SealedLog (or anything with append()),
    keys: KeyStore, jwks: {kid: jwk} of the providers it accepts.
    sunset: unix time after which classical tokens no longer bind."""

    def __init__(self, log, keys, jwks, aud, sunset=None, kem=None, max_session=86400):
        self.log = log
        self.keys = keys
        self.jwks = dict(jwks)
        self.aud = aud
        self.sunset = sunset
        self.kem = kem
        self.max_session = max_session
        self._sessions = {}          # sid -> [vk, t_max, last ctr]
        self._anchors = {}           # bind lsn -> (anchor vk, handle)
        self._sys_sessions = {}
        self._lock = threading.Lock()
        self.log_jwks()

    def log_jwks(self):
        """Log the providers' public keys in clear. Witnessed checkpoints then
        fix which key was current when, so a verifier decades later can take
        the key that signed an old token from the log itself."""
        doc = {kid: {"alg": j["alg"], "key": j["key"].hex()} for kid, j in sorted(self.jwks.items())}
        return self.log.append(self.system_record(public=json.dumps({"jwks": doc}).encode()))

    def _new_binding(self, h, vk, t_max, mode, iss, aud, sub, jwt, r, anchor_lsn=0, anchor_sig=b"",
                     sid=None):
        _, k_s = self.keys.subject(iss, aud, sub)
        sid = sid or os.urandom(16)
        rho = prf(k_s, "bind", sid)
        c_id = H("id", rho, iss, aud, sub)
        c_tok = H("tok", rho, jwt, r)
        self.keys.add_session(sid, h)
        lsn = self.log.append(encode_bind(sid, vk, t_max, mode, c_id, c_tok, anchor_lsn, anchor_sig))
        with self._lock:
            self._sessions[sid] = [vk, t_max, 0]
        return sid, rho, lsn

    def bind(self, message, now=None):
        """message: the client's bind message (bytes), or a KEM envelope if the
        engine has a KEM key. Returns (sid, rho, lsn) or, for envelopes, the
        encrypted reply."""
        key = None
        if self.kem is not None:
            key, message = self.kem.open(message)
        req = json.loads(message)
        now = int(now if now is not None else time.time())
        jwt, vk, t_max, r = req["jwt"], bytes.fromhex(req["vk"]), int(req["t_max"]), bytes.fromhex(req["r"])
        head, claims = oidc.verify_token(jwt, self.jwks, aud=self.aud, now=now)
        a_vk = bytes.fromhex(req.get("anchor_vk", ""))
        if claims["nonce"] != oidc.nonce_for(vk + a_vk, t_max, r):
            raise PolicyError("token nonce does not commit to this session key")
        if not now < t_max <= now + self.max_session:
            raise PolicyError("session lifetime out of policy")
        pq = oidc.is_post_quantum(head["alg"])
        if not pq and self.sunset is not None and now >= self.sunset:
            raise PolicyError("classical tokens are past the sunset; use a PQ token or a continuation")
        iss, aud, sub = claims["iss"], claims["aud"], claims["sub"]
        h, _ = self.keys.subject(iss, aud, sub)
        sid, rho, lsn = self._new_binding(h, vk, t_max, NATIVE if pq else CLASSICAL,
                                          iss, aud, sub, jwt, r)
        if a_vk:
            with self._lock:
                self._anchors[lsn] = (a_vk, h)
        out = (sid, rho, lsn)
        if key is not None:
            return reply(key, json.dumps([sid.hex(), rho.hex(), lsn]).encode())
        return out

    def bind_continuation(self, message, iss, aud, sub, now=None):
        """Bind a new session key with a key anchored in an earlier binding
        (lsn anchor_lsn). The caller has authenticated the user as iss/aud/sub
        some other way (or not at all: a forged claim fails because the anchor
        signature can't be made without the user's anchored key)."""
        req = json.loads(message)
        now = int(now if now is not None else time.time())
        vk, t_max = bytes.fromhex(req["vk"]), int(req["t_max"])
        sid, a_lsn, a_sig = bytes.fromhex(req["sid"]), int(req["anchor_lsn"]), bytes.fromhex(req["anchor_sig"])
        with self._lock:
            anchor = self._anchors.get(a_lsn)
        if anchor is None:
            raise PolicyError("no anchored key at that position")
        a_vk, h = anchor
        if h != self.keys.subject(iss, aud, sub, create=False)[0]:
            raise PolicyError("anchor belongs to a different subject")
        if not mldsa_verify(a_vk, a_sig, continuation_digest(sid, vk, t_max)):
            raise PolicyError("bad anchor signature")
        if not now < t_max <= now + self.max_session:
            raise PolicyError("session lifetime out of policy")
        out = self._new_binding(h, vk, t_max, CONTINUATION, iss, aud, sub, b"", b"",
                                anchor_lsn=a_lsn, anchor_sig=a_sig, sid=sid)
        with self._lock:
            self._anchors[out[2]] = (a_vk, h)
        return out

    def check(self, req, now=None):
        """Admission check for one signed request (raises PolicyError)."""
        now = now if now is not None else time.time()
        with self._lock:
            st = self._sessions.get(req["sid"])
            if st is None:
                raise PolicyError("unknown session")
            vk, t_max, last = st
            if now > t_max:
                raise PolicyError("session expired")
            if req["ctr"] <= last:
                raise PolicyError("replayed or reordered request")
            st[2] = req["ctr"]
        if not mldsa_verify(vk, req["sig"], request_digest(req["sid"], req["ctr"], req["c_m"])):
            raise PolicyError("bad request signature")

    def txn_record(self, req, public=b"", private=b""):
        """Build the TXN record for an admitted request. public: effects that
        are not personal data (logged in clear). private: the subject's own
        effects, encrypted with the subject key together with the request."""
        k_s = self.keys.key_for_session(req["sid"])
        nonce = os.urandom(12)
        ad = pack(req["sid"], req["ctr"], req["c_m"])
        enc = nonce + AESGCM(prf(k_s, "enc")).encrypt(nonce, pack(req["m"], req["rho_m"], private), ad)
        return encode_txn(req["sid"], req["ctr"], req["c_m"], req["sig"], public, enc)

    def admit(self, req, public=b"", private=b"", now=None):
        self.check(req, now)
        return self.log.append(self.txn_record(req, public, private))

    def system_record(self, public=b"", private=b"", subject=None):
        """A record the engine writes on its own account (initial load,
        maintenance), not on behalf of a signed-in user. Personal data in it
        is encrypted under the subject's key like any private record, so the
        database can be rebuilt from the log and erasure still works."""
        if subject is None:
            return bytes([SYS]) + pack(b"", public, b"")
        h, k_s = self.keys.subject(*subject)
        sid = prf(k_s, "sys")[:16]
        if self._sys_sessions.get(sid) is None:
            try:
                self.keys.add_session(sid, h)
            except Exception:
                pass                      # already registered by an earlier run
            self._sys_sessions[sid] = h
        nonce = os.urandom(12)
        enc = nonce + AESGCM(prf(k_s, "enc")).encrypt(nonce, private, pack(sid, b"sys"))
        return bytes([SYS]) + pack(sid, public, enc)

    def erase(self, iss, aud, sub):
        """Erasure: shred the key, then log a marker that carries no identity
        so replicas know to drop the subject's rows."""
        h, k_s = self.keys.subject(iss, aud, sub, create=False)
        tag = prf(k_s, "erase")
        n = self.keys.shred(h)
        lsn = self.log.append(bytes([ERASE]) + pack(tag))
        return lsn, n


def open_txn(keys, rec):
    """Engine side: decrypt a TXN record. -> (m, rho_m, private) or Erased."""
    t = parse_txn(rec)
    k_s = keys.key_for_session(t["sid"])
    nonce, box = t["enc"][:12], t["enc"][12:]
    m, rho_m, private = unpack(AESGCM(prf(k_s, "enc")).decrypt(
        nonce, box, pack(t["sid"], t["ctr"], t["c_m"])))
    return m, rho_m, private


def open_sys(keys, rec):
    """-> (public, private or None if erased)."""
    sid, public, enc = unpack(rec[1:])
    if not sid:
        return public, None
    k_s = keys.key_for_session(sid)
    return public, AESGCM(prf(k_s, "enc")).decrypt(enc[:12], enc[12:], pack(sid, b"sys"))


# --------------------------------------------------------------- witnesses

def checkpoint_message(size, root, digest, t):
    return H("witness", size, root, digest, int(t))


class Witness:
    """An independent party that keeps the newest checkpoint it signed and
    only cosigns checkpoints that extend it (checked with a consistency
    proof) and carry a current time. Its key is post-quantum, otherwise a
    future attacker could forge old checkpoints and backdate a binding."""

    def __init__(self, log_public_key, log_alg, clock_skew=5.0):
        from .signers import verify_signature
        self._verify = verify_signature
        self._sk = mldsa.MLDSA44PrivateKey.generate()
        self.public_bytes = self._sk.public_key().public_bytes_raw()
        self.log_pk, self.log_alg = log_public_key, log_alg
        self.skew = clock_skew
        self.size, self.root = 0, None

    def cosign(self, cp, proof, seal_sig):
        from . import format as fmt
        size, root, digest, t = cp["size"], cp["root"], cp["digest"], cp["time"]
        if abs(t - time.time()) > self.skew:
            raise PolicyError("checkpoint time is not current")
        if not self._verify(self.log_alg, self.log_pk, seal_sig, fmt.signed_message(digest)):
            raise PolicyError("tree head not signed by the log")
        if digest != fmt.seal_digest(cp["seal_no"], cp["first"], size, root, cp["prev"]):
            raise PolicyError("checkpoint fields don't match the seal digest")
        if self.root is not None and size < self.size:
            raise PolicyError("checkpoint goes backwards")
        if self.root is not None and not merkle.verify_consistency(self.size, size, self.root, root, proof):
            raise PolicyError("checkpoint does not extend the last one (fork)")
        self.size, self.root = size, root
        return self._sk.sign(checkpoint_message(size, root, digest, t))


class LocalWitnesses:
    """n witnesses in this process (tests, examples). Real deployments run
    them elsewhere: replica.serve_witness / WitnessClient."""

    def __init__(self, n, log_public_key, log_alg):
        self.ws = [Witness(log_public_key, log_alg) for _ in range(n)]

    @property
    def keys(self):
        return [w.public_bytes for w in self.ws]

    def cosign_all(self, cp, proofs, seal_sig):
        out = []
        for i, (w, proof) in enumerate(zip(self.ws, proofs)):
            try:
                out.append((i, w.cosign(cp, proof, seal_sig)))
            except PolicyError:
                pass
        return out


class Checkpointer:
    """Every `interval` seconds, take the newest signed tree head, get it
    cosigned by the witnesses (each sent a consistency proof from the last
    head it saw) and log the result as a WITNESS record. log needs
    keep_tree=True. client: replica.WitnessClient or anything with
    cosign_all(cp, proofs, seal_sig)."""

    def __init__(self, log, client, n_witnesses, threshold, interval=0.2):
        self.log, self.client = log, client
        self.threshold = threshold
        self.seen = [0] * n_witnesses
        self.interval = interval
        self.rounds = []
        self._stop = threading.Event()
        self._t = None

    def run_once(self):
        head = self.log.signed_head
        if head is None:
            return None
        seal, sig = head
        size = seal.last_lsn
        if size <= max(self.seen):
            return None
        t0 = time.perf_counter()
        cp = {"seal_no": seal.seal_no, "size": size, "root": seal.root, "digest": seal.digest(),
              "time": int(time.time()), "first": seal.first_lsn, "prev": seal.prev_digest}
        tree = self.log.tree
        proofs = [tree.consistency(m, size) if m else [] for m in self.seen]
        cosigs = self.client.cosign_all(cp, proofs, sig)
        for i, _ in cosigs:
            self.seen[i] = size
        if len(cosigs) < self.threshold:
            return None
        cp["frontier"] = frontier_of(tree, size)
        lsn = self.log.append(encode_witness(cp, cosigs))
        self.rounds.append(time.perf_counter() - t0)
        return lsn

    def start(self):
        def loop():
            while not self._stop.wait(self.interval):
                self.run_once()
        self._t = threading.Thread(target=loop, daemon=True)
        self._t.start()

    def stop(self):
        self._stop.set()
        if self._t:
            self._t.join()


def frontier_of(tree, size):
    """Right edge of the tree of the first `size` leaves, as (height, hash)
    pairs: what a verifier needs to start checking at that point."""
    out, off = [], 0
    for k in range(size.bit_length() - 1, -1, -1):
        if size >> k & 1:
            out.append((k, tree.levels[k][off >> k]))
            off += 1 << k
    return out


def encode_witness(cp, cosigs):
    """cosigs: list of (witness index, signature)."""
    fr = b"".join(bytes([k]) + h for k, h in cp.get("frontier", []))
    return bytes([WITNESS]) + pack(cp["seal_no"], cp["size"], cp["root"], cp["digest"], int(cp["time"]),
                                   cp["first"], cp["prev"],
                                   b"".join(struct.pack(">H", i) + pack(s) for i, s in cosigs), fr)


def parse_witness(rec):
    seal_no, size, root, digest, t, first, prev, blob, fr = unpack(rec[1:])
    cosigs, off = [], 0
    while off < len(blob):
        i = struct.unpack_from(">H", blob, off)[0]
        n = int.from_bytes(blob[off + 2:off + 6], "big")
        cosigs.append((i, blob[off + 6:off + 6 + n]))
        off += 6 + n
    frontier = [(fr[i], fr[i + 1:i + 33]) for i in range(0, len(fr), 33)]
    return {"seal_no": u64(seal_no), "size": u64(size), "root": root, "digest": digest,
            "time": u64(t), "first": u64(first), "prev": prev, "frontier": frontier}, cosigs


def witnessed(cp, cosigs, witness_keys, threshold):
    """Number of valid distinct cosignatures >= threshold?"""
    msg = checkpoint_message(cp["size"], cp["root"], cp["digest"], cp["time"])
    ok = {i for i, s in cosigs if 0 <= i < len(witness_keys) and mldsa_verify(witness_keys[i], s, msg)}
    return len(ok) >= threshold


# ----------------------------------------------------------------- receipts

def _log_entries(path):
    """-> (report, seals, leaves, payload by lsn, sigs by seal)."""
    from .verify import _load
    rep, seals, leaves, payloads, sigs = _load(path)
    return rep, seals, leaves, {lsn: p[2] for lsn, p in payloads.items()}, sigs


def _inclusion(lsn, size, leaves):
    return [h.hex() for h in merkle.audit_path(lsn - 1, leaves[:size])]


def make_receipt(path, txn_lsn, keys, opening, witness_count=None, _cache=None):
    """Receipt that record txn_lsn was written by the user behind its session.
    opening: {"iss","aud","sub","jwt","r"} from the user (the engine never
    stores the token). keys: KeyStore, for rho and the record's opening."""
    from .verify import prove
    rep, seals, leaves, payloads, sigs = _cache or _log_entries(path)
    rec = payloads[txn_lsn]
    t = parse_txn(rec)
    m, rho_m, _ = open_txn(keys, rec)
    bind_lsn, b = _find_bind(payloads, t["sid"])
    k_s = keys.key_for_session(t["sid"])
    rho = prf(k_s, "bind", t["sid"])
    out = {"format": "sealwal-provenance-v1",
           "txn": prove(path, txn_lsn), "txn_opening": {"m": m.hex(), "rho_m": rho_m.hex()},
           "bind": prove(path, bind_lsn),
           "bind_opening": {"iss": opening["iss"], "aud": opening["aud"], "sub": opening["sub"],
                            "rho": rho.hex(), "jwt": opening.get("jwt", ""), "r": opening.get("r", b"").hex(),
                            "anchor_vk": opening.get("anchor_vk", b"").hex() if b["mode"] != CONTINUATION else ""}}
    if b["mode"] == CLASSICAL:
        out["checkpoint"] = _covering_checkpoint(payloads, leaves, bind_lsn)
    elif b["mode"] == CONTINUATION:
        a = make_anchor_chain(path, b["anchor_lsn"], keys, opening, (rep, seals, leaves, payloads, sigs))
        out["anchor"] = a
    return out


def make_anchor_chain(path, bind_lsn, keys, opening, cache):
    """Evidence that the binding at bind_lsn is valid (recursively)."""
    from .verify import prove
    rep, seals, leaves, payloads, sigs = cache
    b = parse_bind(payloads[bind_lsn])
    k_s = keys.key_for_session(b["sid"])
    ev = {"bind": prove(path, bind_lsn),
          "bind_opening": {"iss": opening["iss"], "aud": opening["aud"], "sub": opening["sub"],
                           "rho": prf(k_s, "bind", b["sid"]).hex(),
                           "jwt": opening.get("anchor_jwt", ""), "r": opening.get("anchor_r", b"").hex(),
                           "anchor_vk": opening.get("anchor_vk", b"").hex()}}
    if b["mode"] == CLASSICAL:
        ev["checkpoint"] = _covering_checkpoint(payloads, leaves, bind_lsn)
    elif b["mode"] == CONTINUATION:
        ev["anchor"] = make_anchor_chain(path, b["anchor_lsn"], keys, opening, cache)
    return ev


def _find_bind(payloads, sid):
    for lsn in sorted(payloads):
        p = payloads[lsn]
        if p[:1] == bytes([BIND]):
            b = parse_bind(p)
            if b["sid"] == sid:
                return lsn, b
    raise KeyError("no binding for this session")


def _covering_checkpoint(payloads, leaves, lsn):
    """The earliest witness record whose checkpoint covers lsn."""
    for wl in sorted(payloads):
        p = payloads[wl]
        if p[:1] != bytes([WITNESS]):
            continue
        cp, cosigs = parse_witness(p)
        if cp["size"] >= lsn:
            cp.pop("frontier", None)
            return {"cp": {k: (v.hex() if isinstance(v, bytes) else v) for k, v in cp.items()},
                    "cosigs": [(i, s.hex()) for i, s in cosigs],
                    "path": _inclusion(lsn, cp["size"], leaves)}
    raise KeyError("no witnessed checkpoint covers the binding yet")


class Trust:
    """What a verifier needs: the log key, the witnesses, the providers' keys
    (as published when the bindings were made) and the sunset date."""

    def __init__(self, log_alg, log_pk, witness_keys, threshold, jwks, sunset):
        self.log_alg, self.log_pk = log_alg, log_pk
        self.witness_keys, self.threshold = witness_keys, threshold
        self.jwks, self.sunset = jwks, sunset


def _record_of(proof):
    if proof.get("opening") is None:
        raise ValueError("log receipt without its record")
    return bytes.fromhex(proof["opening"]["payload"])


def check_binding(ev, trust, depth=0):
    """-> (bind fields, identity (iss, aud, sub), anchor key registered by
    the user, or b""). Raises ValueError."""
    from .verify import check_proof
    if depth > 16:
        raise ValueError("continuation chain too long")
    ok, why = check_proof(ev["bind"], trust.log_pk)
    if not ok:
        raise ValueError("binding not in the log: " + why)
    b = parse_bind(_record_of(ev["bind"]))
    o = ev["bind_opening"]
    rho = bytes.fromhex(o["rho"])
    ident = (o["iss"], o["aud"], o["sub"])
    if H("id", rho, *ident) != b["c_id"]:
        raise ValueError("identity opening does not match the binding")
    lsn = ev["bind"]["lsn"]
    if b["mode"] in (CLASSICAL, NATIVE):
        jwt, r = o["jwt"], bytes.fromhex(o["r"])
        a_vk = bytes.fromhex(o.get("anchor_vk", ""))
        if H("tok", rho, jwt, r) != b["c_tok"]:
            raise ValueError("token opening does not match the binding")
        head, claims = oidc.verify_token(jwt, trust.jwks, now=None)
        if (claims["iss"], claims["aud"], claims["sub"]) != ident:
            raise ValueError("token is for someone else")
        if claims["nonce"] != oidc.nonce_for(b["vk"] + a_vk, b["t_max"], r):
            raise ValueError("token does not vouch for this session key")
        pq = oidc.is_post_quantum(head["alg"])
        if (b["mode"] == NATIVE) != pq:
            raise ValueError("binding mode doesn't match the token's algorithm")
        if not pq:
            # classical token: only its sealed, witnessed position in time counts
            c = ev.get("checkpoint")
            if c is None:
                raise ValueError("classical binding needs a witnessed checkpoint")
            cp = {k: (bytes.fromhex(v) if k in ("root", "digest", "prev") else v) for k, v in c["cp"].items()}
            if trust.sunset is not None and cp["time"] >= trust.sunset:
                raise ValueError("classical binding was not witnessed before the sunset")
            if not witnessed(cp, [(i, bytes.fromhex(x)) for i, x in c["cosigs"]],
                             trust.witness_keys, trust.threshold):
                raise ValueError("checkpoint lacks enough witness cosignatures")
            leaf = merkle.leaf_hash(lsn, _public_c(ev["bind"]))
            if merkle.root_from_path(lsn - 1, cp["size"], leaf,
                                     [bytes.fromhex(x) for x in c["path"]]) != cp["root"]:
                raise ValueError("binding is not under the witnessed checkpoint")
        return b, ident, a_vk
    if b["mode"] == CONTINUATION:
        if ev["anchor"]["bind"]["lsn"] != b["anchor_lsn"]:
            raise ValueError("continuation points at another binding")
        _, prev_ident, a_vk = check_binding(ev["anchor"], trust, depth + 1)
        if prev_ident != ident:
            raise ValueError("continuation for a different identity")
        if not a_vk or not mldsa_verify(a_vk, b["anchor_sig"],
                                        continuation_digest(b["sid"], b["vk"], b["t_max"])):
            raise ValueError("bad continuation signature")
        return b, ident, a_vk
    raise ValueError("unknown binding mode")


def _public_c(log_proof):
    return bytes.fromhex(log_proof["commitment"])


def check_receipt(rc, trust):
    """-> (True, message) or (False, reason)."""
    from .verify import check_proof
    try:
        if rc.get("format") != "sealwal-provenance-v1":
            raise ValueError("unknown receipt format")
        ok, why = check_proof(rc["txn"], trust.log_pk)
        if not ok:
            raise ValueError("record not in the log: " + why)
        t = parse_txn(_record_of(rc["txn"]))
        m, rho_m = bytes.fromhex(rc["txn_opening"]["m"]), bytes.fromhex(rc["txn_opening"]["rho_m"])
        if H("m", rho_m, m) != t["c_m"]:
            raise ValueError("request opening does not match the record")
        b, ident, _ = check_binding(rc, trust)
        if b["sid"] != t["sid"]:
            raise ValueError("record and binding are different sessions")
        if rc["bind"]["lsn"] >= rc["txn"]["lsn"]:
            raise ValueError("record precedes its binding")
        if not mldsa_verify(b["vk"], t["sig"], request_digest(t["sid"], t["ctr"], t["c_m"])):
            raise ValueError("request not signed by the session key")
    except (ValueError, KeyError, oidc.TokenError) as e:
        return False, str(e)
    return True, (f"record {rc['txn']['lsn']} was requested by {ident[2]} at {ident[0]} "
                  f"(binding {rc['bind']['lsn']}, {MODE_NAMES[b['mode']]})")


# ------------------------------------------------------------- segments

def segment_starts(path, witness_keys=None, threshold=0):
    """Cut points for parallel audits: one per witnessed checkpoint, with the
    state a verifier needs to start there. The frontier is checked against
    the checkpoint's (cosigned) root, so a segment's start can't be faked."""
    from . import format as fmt
    from .verify import scan
    sc = scan(path)
    seal_end, cuts = {}, []
    for off, ftype, body, end in sc.frames:
        if ftype == fmt.SEAL:
            s = fmt.parse_seal(body)
            seal_end[s.seal_no] = (end, s)
        elif ftype == fmt.DATA:
            payload = fmt.parse_data(body)[3]
            if payload[:1] == bytes([WITNESS]):
                cp, cosigs = parse_witness(payload)
                if witness_keys is not None and not witnessed(cp, cosigs, witness_keys, threshold):
                    continue
                f = merkle.Frontier()
                f._stack, f.size = list(cp["frontier"]), cp["size"]
                if not cp["frontier"] or f.root() != cp["root"]:
                    continue
                end_off, _ = seal_end[cp["seal_no"]]
                cuts.append({"offset": end_off, "lsn": cp["size"] + 1, "seal_no": cp["seal_no"] + 1,
                             "prev": cp["digest"], "frontier": cp["frontier"]})
    return cuts


def _verify_segment(args):
    from .verify import verify
    path, pk, start, end = args
    rep = verify(path, pk, start=start, end_offset=end, check_contents=True)
    return rep.ok, rep.errors[:1], rep.seals


def verify_parallel(path, public_key, cuts, workers=2):
    """Verify the log as independent segments between checkpoints."""
    import multiprocessing as mp
    bounds = [None] + cuts
    jobs = [(path, public_key, bounds[i], cuts[i]["offset"] if i < len(cuts) else None)
            for i in range(len(bounds))]
    with mp.get_context("fork").Pool(workers) as pool:
        out = pool.map(_verify_segment, jobs)
    return all(o[0] for o in out), out
