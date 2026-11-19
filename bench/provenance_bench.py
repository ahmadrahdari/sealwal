"""Benchmarks for the provenance layer. Writes results/prov_*.csv.

    python bench/provenance_bench.py [micro receipts keystore audit]
"""

import csv
import json
import os
import statistics
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "tests"))

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa  # noqa: E402

from sealwal import SealedLog, make_signer, verify  # noqa: E402
from sealwal import oidc  # noqa: E402
from sealwal.keystore import KeyStore  # noqa: E402
from sealwal.provenance import (Checkpointer, Engine, EngineKem, Session, Trust, check_receipt,  # noqa: E402
                                make_receipt, seal_envelope, segment_starts, verify_parallel)

OUT = os.path.join(HERE, "..", "results")


def save(name, rows):
    with open(os.path.join(OUT, name), "w", newline="") as f:
        names = []
        for r in rows:
            names += [k for k in r if k not in names]
        w = csv.DictWriter(f, fieldnames=names)
        w.writeheader()
        w.writerows(rows)


def timeit(fn, n=300):
    xs = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        xs.append(time.perf_counter() - t)
    xs.sort()
    return round(xs[len(xs) // 2] * 1e6, 1), round(xs[int(len(xs) * 0.99)] * 1e6, 1)


def micro():
    rows = []

    def add(op, fn, n=300, note=""):
        p50, p99 = timeit(fn, n)
        rows.append({"op": op, "p50_us": p50, "p99_us": p99, "note": note})
        print(rows[-1], flush=True)

    msg = os.urandom(64)
    k = mldsa.MLDSA44PrivateKey.generate()
    pk, sig = k.public_key(), k.sign(msg)
    add("ML-DSA-44 keygen (client, per session)", mldsa.MLDSA44PrivateKey.generate)
    add("ML-DSA-44 sign (client, per request)", lambda: k.sign(msg))
    add("ML-DSA-44 verify (engine, per request)", lambda: pk.verify(sig, msg))
    e = ed25519.Ed25519PrivateKey.generate()
    es = e.sign(msg)
    add("Ed25519 sign (classical baseline)", lambda: e.sign(msg))
    add("Ed25519 verify (classical baseline)", lambda: e.public_key().verify(es, msg))
    idp_rsa, idp_pq = oidc.Provider(alg="RS256"), oidc.Provider(alg="ML-DSA-44")
    s = Session()
    t_rsa, t_pq = idp_rsa.issue("u", "a", s.nonce), idp_pq.issue("u", "a", s.nonce)
    add("ID token verify, RS256", lambda: oidc.verify_token(t_rsa, {idp_rsa.kid: idp_rsa.jwk}))
    add("ID token verify, ML-DSA-44 (RFC 9964)", lambda: oidc.verify_token(t_pq, {idp_pq.kid: idp_pq.jwk}))
    kem = EngineKem()
    bind_msg = s.bind_message(t_rsa)
    add("PQ envelope seal (client, ML-KEM-768)", lambda: seal_envelope(kem.public_bytes, bind_msg))
    _, env = seal_envelope(kem.public_bytes, bind_msg)
    add("PQ envelope open (engine)", lambda: kem.open(env))

    tmp = tempfile.mkdtemp()
    signer = make_signer("lms-hss")
    log = SealedLog.create(os.path.join(tmp, "l.wal"), signer, sync="none", keep_tree=True)
    keys = KeyStore(os.path.join(tmp, "k.db"))
    eng = Engine(log, keys, {idp_rsa.kid: idp_rsa.jwk}, "a")
    cnt = [0]

    def bind():
        cnt[0] += 1
        ss = Session()
        tok = idp_rsa.issue(f"user{cnt[0]}", "a", ss.nonce)
        eng.bind(ss.bind_message(tok))
    add("bind (token check, key store, BIND record)", bind, n=200, note="SQLite synchronous=FULL")
    ss = Session()
    ss.bound(*eng.bind(ss.bind_message(idp_rsa.issue("bench", "a", ss.nonce))))
    reqs = [ss.request(b'{"t":"payment","amount":10}') for _ in range(600)]
    it = iter(reqs)
    add("admission check (session, counter, ML-DSA verify)", lambda: eng.check(next(it)), n=300)
    req = reqs[0]
    add("TXN record (AES-GCM, encode)", lambda: eng.txn_record(req, b"[]", b'[{"row":1}]' * 8))
    log.close()
    save("prov_micro.csv", rows)


def _world(tmp, n, batch=32, every=1000, signer_alg="lms-hss"):
    from sealwal.provenance import LocalWitnesses
    idp = oidc.Provider()
    signer = make_signer(signer_alg)
    path = os.path.join(tmp, "log.wal")
    log = SealedLog.create(path, signer, sync="none", keep_tree=True)
    keys = KeyStore(os.path.join(tmp, "keys.db"), durable=False)
    eng = Engine(log, keys, {idp.kid: idp.jwk}, "app", sunset=time.time() + 3600)
    wit = LocalWitnesses(3, signer.public_bytes, signer_alg)
    cp = Checkpointer(log, wit, 3, 2)
    s = Session()
    jwt = idp.issue("alice", "app", s.nonce)
    s.bound(*eng.bind(s.bind_message(jwt)))
    opening = {"iss": idp.iss, "aud": "app", "sub": "alice", "jwt": jwt, "r": s.r}
    payload = os.urandom(96).hex().encode()
    filler = eng.system_record(public=payload)        # audits check every record the same way
    real = 20
    for i in range(n):
        if i < n - real:
            log.append(filler)
        else:
            eng.admit(s.request(payload), public=b"[]", private=payload)
        if (i + 1) % batch == 0:
            log.commit()
        if (i + 1) % every == 0:
            log.commit()
            cp.run_once()
    log.commit()
    cp.run_once()
    trust = Trust(signer_alg, signer.public_bytes, wit.keys, 2, {idp.kid: idp.jwk}, time.time() + 3600)
    return log, keys, opening, trust, path, signer, wit


def _raw_size(x):
    """Bytes a receipt takes in a binary encoding: hex strings count half."""
    if isinstance(x, dict):
        return sum(len(k) + _raw_size(v) for k, v in x.items())
    if isinstance(x, (list, tuple)):
        return sum(_raw_size(v) for v in x)
    if isinstance(x, str):
        try:
            return len(bytes.fromhex(x)) if len(x) >= 16 else len(x)
        except ValueError:
            return len(x)
    return 8


def receipts():
    rows = []
    for n in (1_000, 10_000, 100_000):
        tmp = tempfile.mkdtemp()
        log, keys, opening, trust, path, signer, wit = _world(tmp, n, every=max(1000, n // 16))
        lsn = log.committed_lsn - 5
        while True:
            from sealwal.verify import _load
            payloads = _load(path)[3]
            if payloads[lsn][2][:1] == b"\x02":
                break
            lsn -= 1
        log.close()
        t = time.perf_counter()
        rc = make_receipt(path, lsn, keys, opening)
        make_s = time.perf_counter() - t
        size = len(json.dumps(rc))
        raw = _raw_size(rc)
        p50, p99 = timeit(lambda: check_receipt(rc, trust), 30)
        ok = check_receipt(rc, trust)[0]
        rows.append({"records": n, "receipt_bytes": raw, "receipt_json_bytes": size, "check_ms_p50": round(p50 / 1000, 2),
                     "check_ms_p99": round(p99 / 1000, 2), "make_s_from_file": round(make_s, 2),
                     "path_hashes": len(rc["txn"]["audit_path"]), "ok": ok})
        print(rows[-1], flush=True)
    save("prov_receipts.csv", rows)


def keystore():
    rows = []
    for n in (10_000, 100_000, 1_000_000, 10_000_000):
        tmp = tempfile.mkdtemp()
        ks = KeyStore(os.path.join(tmp, "k.db"))
        t = time.perf_counter()
        ks.bulk_load(n)
        load_s = time.perf_counter() - t
        hs = []
        for i in range(40):
            h, _ = ks.subject("https://idp", "app", f"victim{i}")
            sid = os.urandom(16)
            ks.add_session(sid, h)
            hs.append((h, sid))
        look = []
        for h, sid in hs:
            ks._cache.clear()
            t = time.perf_counter()
            ks.key_for_session(sid)
            look.append(time.perf_counter() - t)
        lat = []
        for h, _ in hs:
            t = time.perf_counter()
            ks.shred(h)
            lat.append(time.perf_counter() - t)
        lat.sort()
        mb = sum(os.path.getsize(os.path.join(tmp, f)) for f in os.listdir(tmp)) / 1e6
        rows.append({"subjects": n, "load_s": round(load_s, 1), "store_mb": round(mb, 1),
                     "lookup_us_p50": round(statistics.median(look) * 1e6, 1),
                     "shred_ms_p50": round(lat[len(lat) // 2] * 1e3, 2),
                     "shred_ms_p99": round(lat[-1] * 1e3, 2)})
        print(rows[-1], flush=True)
        ks.close()
        import shutil
        shutil.rmtree(tmp)
    save("prov_keystore.csv", rows)


def audit():
    rows = []
    for n in (100_000, 1_000_000):
        tmp = tempfile.mkdtemp()
        log, keys, opening, trust, path, signer, wit = _world(tmp, n, batch=64, every=n // 16)
        log.close()
        mb = os.path.getsize(path) / 1e6
        t = time.perf_counter()
        rep = verify(path, signer.public_bytes)
        one = time.perf_counter() - t
        cuts = segment_starts(path, wit.keys, 2)
        t = time.perf_counter()
        ok, parts = verify_parallel(path, signer.public_bytes, cuts, workers=2)
        two = time.perf_counter() - t
        rows.append({"records": n, "log_mb": round(mb, 1), "segments": len(cuts) + 1,
                     "verify_1core_s": round(one, 2), "verify_2workers_s": round(two, 2),
                     "records_per_s_1core": round(n / one), "ok": rep.ok and ok})
        print(rows[-1], flush=True)
        import shutil
        shutil.rmtree(tmp)
    save("prov_audit.csv", rows)


if __name__ == "__main__":
    for name in sys.argv[1:] or ["micro", "receipts", "keystore", "audit"]:
        globals()[name]()
