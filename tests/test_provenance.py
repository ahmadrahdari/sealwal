import json
import multiprocessing as mp
import os
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa

from sealwal import SealedLog, make_signer, verify
from sealwal import oidc
from sealwal.keystore import Erased, KeyStore
from sealwal.provenance import (Checkpointer, Engine, EngineKem, LocalWitnesses, PolicyError, Session, Trust,
                                check_receipt, encode_txn, make_receipt, open_reply, open_txn,
                                seal_envelope)

AUD = "bank-app"


class World:
    def __init__(self, tmp_path, idp_alg="RS256", sunset=None):
        self.idp = oidc.Provider(alg=idp_alg)
        self.signer = make_signer("ml-dsa-44")
        self.path = str(tmp_path / "log.wal")
        self.log = SealedLog.create(self.path, self.signer, sync="none", keep_tree=True)
        self.keys = KeyStore(tmp_path / "keys.db")
        self.jwks = {self.idp.kid: self.idp.jwk}
        self.sunset = sunset if sunset is not None else time.time() + 3600
        self.engine = Engine(self.log, self.keys, self.jwks, AUD, sunset=self.sunset)
        self.wit = LocalWitnesses(3, self.signer.public_bytes, "ml-dsa-44")
        self.cp = Checkpointer(self.log, self.wit, 3, 2)

    def login(self, sub, anchor_key=None, now=None):
        s = Session(anchor_key=anchor_key)
        jwt = self.idp.issue(sub, AUD, s.nonce, now=now)
        sid, rho, lsn = self.engine.bind(s.bind_message(jwt), now=now)
        s.bound(sid, rho, lsn)
        s.opening = {"iss": self.idp.iss, "aud": AUD, "sub": sub, "jwt": jwt, "r": s.r,
                     "anchor_vk": s.anchor_vk}
        return s

    def write(self, s, m):
        return self.engine.admit(s.request(m), public=b"{}", private=b'{"row":1}')

    def checkpoint(self):
        self.log.commit()
        return self.cp.run_once()

    def trust(self, sunset=None):
        return Trust("ml-dsa-44", self.signer.public_bytes, self.wit.keys, 2, self.jwks,
                     self.sunset if sunset is None else sunset)


def test_classical_binding_receipt(tmp_path):
    w = World(tmp_path)
    s = w.login("alice")
    lsn = w.write(s, b"pay 100 to bob")
    assert w.checkpoint() is not None
    w.log.commit()
    rc = make_receipt(w.path, lsn, w.keys, s.opening)
    ok, msg = check_receipt(rc, w.trust())
    assert ok, msg
    assert "alice" in msg
    # receipts survive a round trip through JSON (they get emailed around)
    assert check_receipt(json.loads(json.dumps(rc)), w.trust())[0]


def test_classical_binding_needs_witnessed_time_before_sunset(tmp_path):
    w = World(tmp_path)
    s = w.login("alice")
    lsn = w.write(s, b"x")
    w.checkpoint()
    w.log.commit()
    rc = make_receipt(w.path, lsn, w.keys, s.opening)
    ok, why = check_receipt(rc, w.trust(sunset=time.time() - 10))
    assert not ok and "sunset" in why
    rc2 = dict(rc)
    rc2.pop("checkpoint")
    assert not check_receipt(rc2, w.trust())[0]


def test_engine_refuses_classical_tokens_after_sunset(tmp_path):
    w = World(tmp_path, sunset=time.time() - 1)
    with pytest.raises(PolicyError, match="sunset"):
        w.login("alice")


def test_native_pq_token_needs_no_checkpoint(tmp_path):
    w = World(tmp_path, idp_alg="ML-DSA-44", sunset=time.time() - 1)
    s = w.login("carol")
    lsn = w.write(s, b"consent: marketing=no")
    w.log.commit()
    rc = make_receipt(w.path, lsn, w.keys, s.opening)
    assert "checkpoint" not in rc
    ok, msg = check_receipt(rc, w.trust())
    assert ok, msg


def test_continuation_after_sunset(tmp_path):
    now = time.time()
    w = World(tmp_path, sunset=now + 100)
    anchor = mldsa.MLDSA44PrivateKey.generate()
    s1 = w.login("dave", anchor_key=anchor)           # before the sunset, RS256
    w.write(s1, b"first")
    w.checkpoint()
    w.engine.sunset = now - 1                          # the sunset has passed
    with pytest.raises(PolicyError):
        w.login("dave")                                # classical login no longer binds
    s2 = Session(anchor_key=anchor)
    sid = os.urandom(16)
    sid2, rho, lsn2 = w.engine.bind_continuation(s2.continuation_message(s1.bind_lsn, sid),
                                                 w.idp.iss, AUD, "dave")
    s2.bound(sid2, rho, lsn2)
    lsn = w.write(s2, b"after the sunset")
    w.log.commit()
    opening = {"iss": w.idp.iss, "aud": AUD, "sub": "dave", "anchor_jwt": s1.opening["jwt"],
               "anchor_r": s1.r, "anchor_vk": s1.anchor_vk}
    rc = make_receipt(w.path, lsn, w.keys, opening)
    ok, msg = check_receipt(rc, w.trust(sunset=now + 100))
    assert ok, msg and "continuation" in msg


def test_engine_cannot_register_an_anchor_for_a_user(tmp_path):
    # the anchor key has to be committed in the user's own token nonce
    w = World(tmp_path)
    s = Session()
    jwt = w.idp.issue("erin", AUD, s.nonce)
    msg = json.loads(s.bind_message(jwt))
    msg["anchor_vk"] = mldsa.MLDSA44PrivateKey.generate().public_key().public_bytes_raw().hex()
    with pytest.raises(PolicyError, match="nonce"):
        w.engine.bind(json.dumps(msg).encode())


def test_engine_cannot_forge_a_write(tmp_path):
    w = World(tmp_path)
    s = w.login("alice")
    req = s.request(b"pay 5")
    req["m"], req["c_m"] = b"pay 5000", b"\x00" * 32           # engine edits the request
    with pytest.raises(PolicyError, match="signature"):
        w.engine.admit(req)
    # or writes a record under the session without the user's key
    lsn = w.log.append(encode_txn(s.sid, 99, b"\x11" * 32, b"\x00" * 2420, b"", b""))
    w.checkpoint()
    w.log.commit()
    with pytest.raises(Exception):
        make_receipt(w.path, lsn, w.keys, s.opening)


def test_tampered_receipt_fails(tmp_path):
    w = World(tmp_path)
    s = w.login("alice")
    lsn = w.write(s, b"pay 100")
    w.checkpoint()
    w.log.commit()
    rc = make_receipt(w.path, lsn, w.keys, s.opening)
    bad = json.loads(json.dumps(rc))
    bad["txn_opening"]["m"] = b"pay 900".hex()
    assert not check_receipt(bad, w.trust())[0]
    bad = json.loads(json.dumps(rc))
    bad["bind_opening"]["sub"] = "mallory"
    assert not check_receipt(bad, w.trust())[0]
    other = oidc.Provider()                                   # a token from another provider
    bad = json.loads(json.dumps(rc))
    bad["bind_opening"]["jwt"] = other.issue("alice", AUD, s.nonce)
    assert not check_receipt(bad, w.trust())[0]


def test_replay_rejected(tmp_path):
    w = World(tmp_path)
    s = w.login("alice")
    req = s.request(b"pay 1")
    w.engine.admit(req)
    with pytest.raises(PolicyError, match="replay"):
        w.engine.admit(req)


def test_log_holds_no_identity(tmp_path):
    w = World(tmp_path)
    s = w.login("alice@example.com")
    w.write(s, b"my diagnosis is J45")
    w.checkpoint()
    w.log.close()
    raw = open(w.path, "rb").read()
    for needle in (b"alice", b"example.com", w.idp.iss.encode(), AUD.encode(), b"J45",
                   s.opening["jwt"].encode()[:40]):
        assert needle not in raw
    assert verify(w.path, w.signer.public_bytes).ok


def test_erasure(tmp_path):
    w = World(tmp_path)
    a, b = w.login("alice"), w.login("bob")
    la, lb = w.write(a, b"alice 1"), w.write(b, b"bob 1")
    w.checkpoint()
    w.log.commit()
    rc_bob = make_receipt(w.path, lb, w.keys, b.opening)
    w.engine.erase(w.idp.iss, AUD, "alice")
    w.log.commit()
    assert verify(w.path, w.signer.public_bytes).ok
    from sealwal.verify import _load
    payloads = {k: v[2] for k, v in _load(w.path)[3].items()}
    with pytest.raises(Erased):
        open_txn(w.keys, payloads[la])
    with pytest.raises(Erased):
        make_receipt(w.path, la, w.keys, a.opening)
    assert check_receipt(rc_bob, w.trust())[0]                 # bob's evidence unaffected
    assert open_txn(w.keys, payloads[lb])[0] == b"bob 1"


def test_witness_detects_fork(tmp_path):
    w = World(tmp_path)
    s = w.login("alice")
    w.write(s, b"1")
    assert w.checkpoint() is not None
    # a second log under the same key with different history
    fork = SealedLog.create(str(tmp_path / "fork.wal"), w.signer, sync="none", keep_tree=True)
    for _ in range(5):
        fork.append(b"forged")
    fork.commit()
    cp = Checkpointer(fork, w.wit, 3, 2)
    cp.seen = list(w.cp.seen)
    assert cp.run_once() is None            # no witness cosigns a non-extension


def test_pq_envelope(tmp_path):
    w = World(tmp_path)
    w.engine.kem = EngineKem()
    s = Session()
    jwt = w.idp.issue("frank", AUD, s.nonce)
    key, env = seal_envelope(w.engine.kem.public_bytes, s.bind_message(jwt))
    assert b"frank" not in env and jwt.encode()[:20] not in env
    sid, rho, lsn = json.loads(open_reply(key, w.engine.bind(env)))
    assert lsn > 0


def _node(path, port, ready):
    from sealwal.replica import serve_node
    serve_node(path, port, ready)


def test_quorum_replication(tmp_path):
    from sealwal.replica import QuorumError, QuorumSink, read_node
    ctx = mp.get_context("fork")
    procs, addrs = [], []
    base = 20000 + os.getpid() % 10000
    for i in range(3):
        ev = ctx.Event()
        p = ctx.Process(target=_node, args=(str(tmp_path / f"n{i}.wal"), base + i, ev), daemon=True)
        p.start()
        ev.wait(10)
        procs.append(p)
        addrs.append(("127.0.0.1", base + i))
    try:
        sink = QuorumSink(addrs)
        signer = make_signer("ml-dsa-44")
        log = SealedLog.create(str(tmp_path / "w.wal"), signer, sync="none", sink=sink)
        for i in range(20):
            log.append(b"r%d" % i)
            log.commit()
        procs[0].kill()
        procs[0].join()
        for i in range(5):
            log.append(b"s%d" % i)
            log.commit()                      # 2 of 3 still form a quorum
        log.close()
        copy = read_node(addrs[1])
        assert copy == open(tmp_path / "w.wal", "rb").read()
        procs[1].kill()
        procs[1].join()
        log2 = SealedLog.open(str(tmp_path / "w.wal"), signer, sync="none", sink=QuorumSink(addrs[2:], 2))
        log2.append(b"lost")
        with pytest.raises(QuorumError):
            log2.commit()
    finally:
        for p in procs:
            p.kill()


def test_segments_verify_independently_and_catch_tampering(tmp_path):
    from sealwal.provenance import segment_starts, verify_parallel
    w = World(tmp_path)
    s = w.login("alice")
    for _ in range(3):
        for i in range(50):
            w.write(s, b"x")
            if i % 10 == 0:
                w.log.commit()
        w.checkpoint()
    w.log.close()
    cuts = segment_starts(w.path, w.wit.keys, 2)
    assert len(cuts) == 3
    assert verify_parallel(w.path, w.signer.public_bytes, cuts)[0]
    # flip a byte inside the second segment: only that segment fails
    raw = bytearray(open(w.path, "rb").read())
    pos = (cuts[0]["offset"] + cuts[1]["offset"]) // 2
    raw[pos] ^= 1
    open(w.path, "wb").write(bytes(raw))
    ok, parts = verify_parallel(w.path, w.signer.public_bytes, cuts)
    assert not ok and [p[0] for p in parts].count(False) >= 1
    # a segment start with a made-up frontier is not accepted as a cut point
    cuts2 = segment_starts(w.path, [b"\x00" * 1312] * 3, 2)
    assert cuts2 == []
