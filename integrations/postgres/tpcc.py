"""PostgreSQL front end with sealwal as the log of record, plus the TPC-C-like
and YCSB drivers used in the evaluation.

Write path of one transaction (provenance configurations):
  1. the user's request arrives signed with the session key (pre-signed by
     the driver: signing happens on the user's device, not on the server)
  2. Engine.check: session known, counter fresh, ML-DSA-44 signature valid
  3. BEGIN; SELECT new_order(...) / payment(...) -> after-images
  4. TXN record (request commitment, signature, public images in clear,
     private images + request encrypted under the subject key) goes to the
     group committer, which seals it and waits for a quorum of log nodes
  5. COMMIT (synchronous_commit=off: durability comes from the log)

Configurations:
  pg-sync      stock PostgreSQL, synchronous commit, no external log
  plain-log    same front end and replicated log, no signatures, no
               privacy (user id and images in clear): the cost of the
               architecture without any of sealwal's cryptography
  classical    Ed25519 session keys and Ed25519 seals (what you'd build
               without post-quantum requirements)
  sealwal      ML-DSA-44 session keys, private records, epoch HSS seals,
               witnessed checkpoints
  sealwal-mldsa  same with inline ML-DSA-44 seals instead of HSS
  sealwal-k4   same as sealwal with bounded asynchronous seals, K=4
"""

import json
import multiprocessing as mp
import os
import random
import shutil
import statistics
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

from pgwire import Conn, PgError, lit  # noqa: E402
from sealwal import GroupCommitter, SealedLog, make_signer  # noqa: E402
from sealwal import oidc  # noqa: E402
from sealwal.keystore import KeyStore  # noqa: E402
from sealwal.provenance import Checkpointer, Engine, Session  # noqa: E402
from sealwal.replica import QuorumSink, WitnessClient, serve_node, serve_witness  # noqa: E402

SCALE = {"W": 2, "D": 10, "C": 300, "I": 10_000, "YCSB_KEYS": 100_000}
AUD = "orders-app"

CONFIGS = {
    "pg-sync": {"pg_sync": True, "log": None},
    "plain-log": {"pg_sync": False, "log": {"alg": "none", "prov": False}},
    "classical": {"pg_sync": False, "log": {"alg": "ed25519", "prov": True, "session": "ed25519"}},
    "sealwal": {"pg_sync": False, "log": {"alg": "lms-hss", "prov": True}},
    "sealwal-mldsa": {"pg_sync": False, "log": {"alg": "ml-dsa-44", "prov": True}},
    "sealwal-k4": {"pg_sync": False, "log": {"alg": "lms-hss", "prov": True, "async": 4}},
}


# ------------------------------------------------------------------ loading

def load(scale=SCALE):
    c = Conn()
    c.query(open(os.path.join(HERE, "schema.sql")).read())
    rnd = random.Random(7)

    def bulk(table, rows, chunk=2000):
        for i in range(0, len(rows), chunk):
            vals = ",".join("(" + ",".join(lit(v) for v in r) + ")" for r in rows[i:i + chunk])
            c.query(f"INSERT INTO {table} VALUES {vals}")

    W, D, C, I = scale["W"], scale["D"], scale["C"], scale["I"]
    bulk("warehouse", [(w, f"wh{w}", 300000.0) for w in range(1, W + 1)])
    bulk("district", [(w, d, f"d{d}", 30000.0, 1) for w in range(1, W + 1) for d in range(1, D + 1)])
    bulk("item", [(i, f"item{i}", round(rnd.uniform(1, 100), 2)) for i in range(1, I + 1)])
    bulk("stock", [(w, i, rnd.randint(10, 100), 0, 0) for w in range(1, W + 1) for i in range(1, I + 1)])
    bulk("customer", [(w, d, k, f"first{k}", f"last{k % 1000}", f"{k} main st", "city", -10.0, 10.0, 1,
                       "x" * 300) for w in range(1, W + 1) for d in range(1, D + 1) for k in range(1, C + 1)])
    bulk("usertable", [(k, k % 1000, "v" * 100) for k in range(scale["YCSB_KEYS"])], chunk=5000)
    c.query("VACUUM ANALYZE")
    c.close()


def subject_of(w, d, k):
    return f"cust-{w}-{d}-{k}"


# --------------------------------------------------------------- workloads

class Zipf:
    def __init__(self, n, theta=0.99, seed=1):
        import bisect
        self._bisect = bisect.bisect
        w = [1 / (i + 1) ** theta for i in range(n)]
        tot = sum(w)
        acc, self.cdf = 0.0, []
        for x in w:
            acc += x / tot
            self.cdf.append(acc)
        self.rnd = random.Random(seed)

    def next(self):
        return min(self._bisect(self.cdf, self.rnd.random()), len(self.cdf) - 1)


def tpcc_request(rnd, w, d, k, scale=SCALE):
    if rnd.random() < 0.5:
        n = rnd.randint(5, 15)
        items = sorted(rnd.sample(range(1, scale["I"] + 1), n))   # sorted: no deadlocks
        return {"t": "new_order", "w": w, "d": d, "c": k, "items": items,
                "qtys": [rnd.randint(1, 10) for _ in items]}
    return {"t": "payment", "w": w, "d": d, "c": k, "amount": round(rnd.uniform(1, 5000), 2)}


def to_sql(req):
    if req["t"] == "new_order":
        arr = lambda xs: "ARRAY[" + ",".join(map(str, xs)) + "]::int[]"   # noqa: E731
        return f"SELECT new_order({req['w']},{req['d']},{req['c']},{arr(req['items'])},{arr(req['qtys'])})"
    if req["t"] == "payment":
        return f"SELECT payment({req['w']},{req['d']},{req['c']},{req['amount']})"
    if req["t"] == "update":
        return f"SELECT ycsb_update({req['k']},{lit(req['v'])})"
    raise ValueError(req["t"])


# ------------------------------------------------------------ infrastructure

class Cluster:
    """Three log nodes and three witnesses, each its own process."""

    def __init__(self, base_port, witnesses=3, nodes=3, log_pk=b"", log_alg="none"):
        self.tmp = tempfile.mkdtemp(prefix="sealwal-cluster-", dir="/tmp")
        # forkserver: children must not inherit the writer's threads or file
        # locks (a child holding a copy of the epoch lock would stall the signer)
        ctx = mp.get_context("forkserver")
        self.procs, self.nodes, self.witnesses, self.wkeys = [], [], [], []
        for i in range(nodes):
            ev = ctx.Event()
            p = ctx.Process(target=serve_node, args=(os.path.join(self.tmp, f"node{i}.wal"), base_port + i, ev),
                            daemon=True)
            p.start()
            ev.wait(10)
            self.procs.append(p)
            self.nodes.append(("127.0.0.1", base_port + i))
        if witnesses and log_alg != "none":
            q = ctx.Queue()
            for i in range(witnesses):
                ev = ctx.Event()
                port = base_port + 10 + i
                p = ctx.Process(target=serve_witness, args=(log_pk, log_alg, port, ev, q), daemon=True)
                p.start()
                ev.wait(10)
                self.procs.append(p)
                self.witnesses.append(("127.0.0.1", port))
                self.wkeys.append(q.get(timeout=10))

    def stop(self):
        for p in self.procs:
            p.kill()
            p.join()
        shutil.rmtree(self.tmp, ignore_errors=True)


def _classical_session(s):
    """Classical baseline: an Ed25519 session key instead of ML-DSA-44."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    s._sk = ed25519.Ed25519PrivateKey.generate()
    s.vk = s._sk.public_key().public_bytes_raw()
    s.nonce = oidc.nonce_for(s.vk, s.t_max, s.r)


# ------------------------------------------------------------------- runner

def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else float("nan")


def run(config_name, workload="tpcc", clients=8, seconds=15.0, base_port=31000, users_per_client=16,
        reqs_per_client=None, seed=1, out=None):
    cfg = CONFIGS[config_name]
    rnd = random.Random(seed)
    lcfg = cfg["log"]
    tmp = tempfile.mkdtemp(prefix="sealwal-run-", dir="/tmp")
    cluster = log = gc = engine = cp = keys = None
    try:
        if lcfg is not None:
            alg = lcfg["alg"]
            signer = make_signer(alg) if alg != "lms-hss" else make_signer(alg)
            cluster = Cluster(base_port, log_pk=signer.public_bytes, log_alg=alg)
            sink = QuorumSink(cluster.nodes)
            opts = dict(sync="none", sink=sink, keep_tree=True)
            if lcfg.get("async"):
                opts.update(async_sign=True, max_unsigned=lcfg["async"])
            log = SealedLog.create(os.path.join(tmp, "writer.wal"), signer, **opts)
            gc = GroupCommitter(log)
            if lcfg["prov"]:
                idp = oidc.Provider(alg="RS256")
                keys = KeyStore(os.path.join(tmp, "keys.db"))
                engine = Engine(log, keys, {idp.kid: idp.jwk}, AUD, sunset=time.time() + 86400)
                wc = WitnessClient(cluster.witnesses)
                cp = Checkpointer(log, wc, len(cluster.witnesses), 2, interval=0.2)

        # users and their pre-signed requests (signing is the device's work)
        W, D, C = SCALE["W"], SCALE["D"], SCALE["C"]
        zipf = Zipf(SCALE["YCSB_KEYS"]) if workload != "tpcc" else None
        per_client = []
        per_s = {"tpcc": 3000 if clients == 1 else 1200 if clients <= 4 else 400,
                 "ycsb-a": 900}.get(workload, 4000)
        n_req = reqs_per_client or int(seconds * per_s)
        for ci in range(clients):
            users = []
            for _ in range(users_per_client):
                w, d, k = rnd.randint(1, W), rnd.randint(1, D), rnd.randint(1, C)
                users.append((w, d, k))
            sessions = {}
            if engine is not None:
                for u in users:
                    s = Session(lifetime=3600)
                    if lcfg.get("session") == "ed25519":
                        _classical_session(s)
                    jwt = idp.issue(subject_of(*u), AUD, s.nonce)
                    s.bound(*engine.bind(s.bind_message(jwt)))
                    sessions[u] = s
            reqs = []
            for i in range(n_req):
                u = users[i % len(users)]
                if workload == "tpcc":
                    r = tpcc_request(rnd, *u)
                else:
                    read_frac = {"ycsb-a": 0.5, "ycsb-b": 0.95}[workload]
                    k = zipf.next()
                    r = ({"t": "read", "k": k} if rnd.random() < read_frac
                         else {"t": "update", "k": k, "v": "%032x" % rnd.getrandbits(128) * 3})
                m = json.dumps(r, separators=(",", ":")).encode()
                signed = None
                if engine is not None and r["t"] != "read":
                    if lcfg.get("session") == "ed25519":
                        signed = _ed_request(sessions[u], m)
                    else:
                        signed = sessions[u].request(m)
                reqs.append((u, r, m, signed))
            per_client.append(reqs)
        if engine is not None and lcfg.get("session") == "ed25519":
            engine.check = _ed_check(engine)          # classical baseline verifies Ed25519
        if log is not None:
            log.commit()
        if cp is not None:
            cp.start()

        lat, aborts, stop = [[] for _ in range(clients)], [0] * clients, threading.Event()
        done = [0] * clients

        def client(ci):
            conn = Conn()
            conn.query("SET synchronous_commit = " + ("on" if cfg["pg_sync"] else "off"))
            for u, r, m, signed in per_client[ci]:
                if stop.is_set():
                    break
                t0 = time.perf_counter()
                try:
                    if r["t"] == "read":
                        conn.query(f"SELECT field0 FROM usertable WHERE ycsb_key = {r['k']}")
                    else:
                        if engine is not None:
                            engine.check(signed)
                        res = conn.query("BEGIN; " + to_sql(r))
                        if gc is not None:
                            images = json.loads(res[0][0])
                            if engine is not None:
                                rec = engine.txn_record(signed, json.dumps(images["public"]).encode(),
                                                        json.dumps(images["private"]).encode())
                            else:
                                rec = json.dumps({"user": subject_of(*u), "req": r, "images": images}).encode()
                            gc.submit(rec)
                        conn.query("COMMIT")
                except PgError:
                    aborts[ci] += 1
                    conn.query("ROLLBACK")
                    continue
                lat[ci].append(time.perf_counter() - t0)
                done[ci] += 1
            conn.close()

        ts = [threading.Thread(target=client, args=(i,)) for i in range(clients)]
        t0 = time.perf_counter()
        for t in ts:
            t.start()
        time.sleep(seconds)
        stop.set()
        for t in ts:
            t.join()
        took = time.perf_counter() - t0
        if cp is not None:
            cp.stop()
        allv = [x for xs in lat for x in xs]
        res = {"config": config_name, "workload": workload, "clients": clients, "seconds": round(took, 2),
               "ops": len(allv), "tps": round(len(allv) / took, 1),
               "p50_ms": round(pct(allv, 0.5) * 1e3, 3), "p99_ms": round(pct(allv, 0.99) * 1e3, 3),
               "p999_ms": round(pct(allv, 0.999) * 1e3, 3), "aborts": sum(aborts),
               "ran_out": any(len(lat[i]) + aborts[i] >= len(per_client[i]) for i in range(clients))}
        if gc is not None:
            res["avg_batch"] = round(statistics.mean(gc.batches), 2) if gc.batches else 0
            res["log_bytes"] = os.path.getsize(log.path)
            res["bytes_per_write"] = round(res["log_bytes"] / max(1, log.committed_lsn), 1)
        if cp is not None:
            res["checkpoints"] = len(cp.rounds)
            res["checkpoint_ms_p50"] = round(pct(cp.rounds, 0.5) * 1e3, 2) if cp.rounds else None
        if out is not None:
            out.update({"log": log.path if log else None, "keys": keys})
        return res
    finally:
        if gc is not None:
            gc.close()
        if log is not None:
            log.close()
        if cluster is not None:
            cluster.stop()
        if out is None:
            shutil.rmtree(tmp, ignore_errors=True)


def _ed_request(s, m):
    from sealwal.provenance import H, request_digest
    s.ctr += 1
    rho_m = os.urandom(32)
    c_m = H("m", rho_m, m)
    return {"sid": s.sid, "ctr": s.ctr, "m": m, "rho_m": rho_m, "c_m": c_m,
            "sig": s._sk.sign(request_digest(s.sid, s.ctr, c_m))}


def _ed_check(engine):
    """Classical baseline: same admission logic, Ed25519 verification."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    from sealwal.provenance import PolicyError, request_digest
    def check(req, now=None):
        with engine._lock:
            st = engine._sessions[req["sid"]]
            if req["ctr"] <= st[2]:
                raise PolicyError("replay")
            st[2] = req["ctr"]
        pk = ed25519.Ed25519PublicKey.from_public_bytes(st[0])
        try:
            pk.verify(req["sig"], request_digest(req["sid"], req["ctr"], req["c_m"]))
        except InvalidSignature:
            raise PolicyError("bad signature")
    return check


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--load", action="store_true")
    ap.add_argument("--config", default="sealwal")
    ap.add_argument("--workload", default="tpcc")
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--seconds", type=float, default=10)
    a = ap.parse_args()
    if a.load:
        load()
    print(json.dumps(run(a.config, a.workload, a.clients, a.seconds)))
