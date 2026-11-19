"""The log is the database: rebuild PostgreSQL from the sealed log alone,
after some customers were erased, and compare with the live database.

    python integrations/postgres/replay.py

1. empty schema; the initial load goes through the log (public rows in
   clear, each customer's row encrypted under that customer's key)
2. a few thousand signed TPC-C-like transactions
3. erase some customers: shred their keys, log ERASE, delete their rows
4. replay the log into a fresh database: public images always apply,
   private images only while the subject's key exists
5. compare every table, row by row (md5 over the ordered rows)
"""

import csv
import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import tpcc  # noqa: E402
from pgwire import Conn, PgError, lit  # noqa: E402
from sealwal import GroupCommitter, SealedLog, make_signer, verify  # noqa: E402
from sealwal import format as fmt  # noqa: E402
from sealwal import oidc  # noqa: E402
from sealwal.keystore import Erased, KeyStore  # noqa: E402
from sealwal.provenance import (SYS, TXN, Checkpointer, Engine, Session, open_sys, open_txn,  # noqa: E402
                                parse_txn, unpack)
from sealwal.replica import QuorumSink, WitnessClient  # noqa: E402
from sealwal.verify import scan  # noqa: E402

PK = {"warehouse": ["w_id"], "district": ["d_w_id", "d_id"], "customer": ["c_w_id", "c_d_id", "c_id"],
      "item": ["i_id"], "stock": ["s_w_id", "s_i_id"], "orders": ["o_w_id", "o_d_id", "o_id"],
      "new_order": ["no_w_id", "no_d_id", "no_o_id"],
      "order_line": ["ol_w_id", "ol_d_id", "ol_o_id", "ol_number"], "history": ["h_id"]}
SCALE = {"W": 1, "D": 10, "C": 300, "I": 5000}


def upsert_sql(img):
    t, r = img["t"], img["r"]
    cols = list(r)
    sets = ",".join(f"{c}=EXCLUDED.{c}" for c in cols if c not in PK[t])
    return (f"INSERT INTO {t} ({','.join(cols)}) VALUES ({','.join(lit(r[c]) for c in cols)}) "
            f"ON CONFLICT ({','.join(PK[t])}) DO " + (f"UPDATE SET {sets}" if sets else "NOTHING"))


def apply(conn, images, chunk=200):
    for i in range(0, len(images), chunk):
        conn.query(";".join(upsert_sql(x) for x in images[i:i + chunk]))


def fresh_db(name):
    c = Conn(database="postgres")
    c.query(f"DROP DATABASE IF EXISTS {name}")
    c.query(f"CREATE DATABASE {name}")
    c.close()
    c = Conn(database=name)
    c.query(open(os.path.join(HERE, "schema.sql")).read())
    return c


def table_digest(conn, t):
    order = ",".join(PK[t])
    return conn.query(f"SELECT count(*), md5(coalesce(string_agg(x::text, '|' ORDER BY {order}), '')) "
                      f"FROM {t} x")[0]


def main(n_txn=4000, n_erase=30, threads=4):
    tmp = tempfile.mkdtemp(prefix="sealwal-replay-", dir="/tmp")
    rnd = random.Random(3)
    signer = make_signer("lms-hss")
    cluster = tpcc.Cluster(33500, log_pk=signer.public_bytes, log_alg="lms-hss")
    live = fresh_db("live")
    try:
        sink = QuorumSink(cluster.nodes)
        log = SealedLog.create(os.path.join(tmp, "writer.wal"), signer, sync="none", sink=sink, keep_tree=True)
        gc = GroupCommitter(log)
        idp = oidc.Provider()
        keys = KeyStore(os.path.join(tmp, "keys.db"))
        engine = Engine(log, keys, {idp.kid: idp.jwk}, tpcc.AUD, sunset=time.time() + 86400)
        cp = Checkpointer(log, WitnessClient(cluster.witnesses), 3, 2, interval=0.2)
        cp.start()

        # 1. initial load through the log
        t0 = time.perf_counter()
        W, D, C, I = SCALE["W"], SCALE["D"], SCALE["C"], SCALE["I"]
        pub = ([{"t": "warehouse", "r": {"w_id": w, "w_name": f"wh{w}", "w_ytd": 300000.0}} for w in range(1, W + 1)]
               + [{"t": "district", "r": {"d_w_id": w, "d_id": d, "d_name": f"d{d}", "d_ytd": 30000.0,
                                          "d_next_o_id": 1}} for w in range(1, W + 1) for d in range(1, D + 1)]
               + [{"t": "item", "r": {"i_id": i, "i_name": f"item{i}", "i_price": round(rnd.uniform(1, 100), 2)}}
                  for i in range(1, I + 1)]
               + [{"t": "stock", "r": {"s_w_id": w, "s_i_id": i, "s_quantity": rnd.randint(10, 100), "s_ytd": 0,
                                       "s_order_cnt": 0}} for w in range(1, W + 1) for i in range(1, I + 1)])
        for i in range(0, len(pub), 500):
            gc.submit(engine.system_record(public=json.dumps(pub[i:i + 500]).encode()))
        apply(live, pub)
        custs = [(w, d, k) for w in range(1, W + 1) for d in range(1, D + 1) for k in range(1, C + 1)]
        for (w, d, k) in custs:
            row = [{"t": "customer", "r": {"c_w_id": w, "c_d_id": d, "c_id": k, "c_first": f"first{k}",
                                           "c_last": f"last{k}", "c_street": f"{k} main st", "c_city": "city",
                                           "c_balance": -10.0, "c_ytd_payment": 10.0, "c_payment_cnt": 1,
                                           "c_data": "x" * 50}}]
            log.append(engine.system_record(private=json.dumps(row).encode(),
                                            subject=(idp.iss, tpcc.AUD, tpcc.subject_of(w, d, k))))
            apply(live, row)
        log.commit()
        load_s = time.perf_counter() - t0

        # 2. signed transactions
        sessions = {}
        for u in custs:
            s = Session()
            s.bound(*engine.bind(s.bind_message(idp.issue(tpcc.subject_of(*u), tpcc.AUD, s.nonce))))
            sessions[u] = s
        work = [[] for _ in range(threads)]
        for i in range(n_txn):
            u = rnd.choice(custs)
            r = tpcc.tpcc_request(rnd, *u, scale=SCALE)
            work[hash(u) % threads].append((u, r))
        for lst in work:            # sign in order per session
            for j, (u, r) in enumerate(lst):
                lst[j] = (u, r, sessions[u].request(json.dumps(r).encode()))
        aborts = [0]

        def client(lst):
            conn = Conn(database="live")
            conn.query("SET synchronous_commit = off")
            for u, r, req in lst:
                try:
                    engine.check(req)
                    res = conn.query("BEGIN; " + tpcc.to_sql(r))
                    img = json.loads(res[0][0])
                    gc.submit(engine.txn_record(req, json.dumps(img["public"]).encode(),
                                                json.dumps(img["private"]).encode()))
                    conn.query("COMMIT")
                except PgError:
                    conn.query("ROLLBACK")
                    aborts[0] += 1
            conn.close()
        t1 = time.perf_counter()
        ts = [threading.Thread(target=client, args=(lst,)) for lst in work]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        run_s = time.perf_counter() - t1

        # 3. erasure
        erased = rnd.sample(custs, n_erase)
        for (w, d, k) in erased:
            engine.erase(idp.iss, tpcc.AUD, tpcc.subject_of(w, d, k))
            live.query(f"BEGIN; DELETE FROM order_line USING orders WHERE ol_w_id=o_w_id AND ol_d_id=o_d_id "
                       f"AND ol_o_id=o_id AND o_w_id={w} AND o_d_id={d} AND o_c_id={k}; "
                       f"DELETE FROM new_order USING orders WHERE no_w_id=o_w_id AND no_d_id=o_d_id "
                       f"AND no_o_id=o_id AND o_w_id={w} AND o_d_id={d} AND o_c_id={k}; "
                       f"DELETE FROM orders WHERE o_w_id={w} AND o_d_id={d} AND o_c_id={k}; "
                       f"DELETE FROM history WHERE h_c_w_id={w} AND h_c_d_id={d} AND h_c_id={k}; "
                       f"DELETE FROM customer WHERE c_w_id={w} AND c_d_id={d} AND c_id={k}; COMMIT")
        log.commit()
        cp.stop()
        cp.run_once()
        gc.close()
        log.close()

        # 4. replay from the log
        t2 = time.perf_counter()
        rep = verify(log.path, signer.public_bytes)
        verify_s = time.perf_counter() - t2
        assert rep.ok, rep.errors
        replica = fresh_db("replayed")
        t3 = time.perf_counter()
        n_rec = n_skip = 0
        batch = []
        for _, ftype, body, _ in scan(log.path).frames:
            if ftype != fmt.DATA:
                continue
            rec = fmt.parse_data(body)[3]
            kind = rec[0]
            if kind == SYS:
                public, private = None, None
                try:
                    public, private = open_sys(keys, rec)
                except Erased:
                    public = unpack(rec[1:])[1]
                    n_skip += 1
                for part in (public, private):
                    images = json.loads(part) if part else []
                    if isinstance(images, list):      # skip JWKS snapshots
                        batch += images
            elif kind == TXN:
                t = parse_txn(rec)
                batch += json.loads(t["public"]) if t["public"] else []
                try:
                    batch += json.loads(open_txn(keys, rec)[2])
                except Erased:
                    n_skip += 1
            n_rec += 1
            if len(batch) > 400:
                apply(replica, batch)
                batch = []
        apply(replica, batch)
        replay_s = time.perf_counter() - t3

        # 5. compare
        rows, same = [], True
        for t in PK:
            a, b = table_digest(live, t), table_digest(replica, t)
            same &= a == b
            rows.append({"table": t, "live_rows": a[0], "replayed_rows": b[0], "match": a == b})
        summary = {"records": n_rec, "txns": n_txn, "aborts": aborts[0], "erased_customers": n_erase,
                   "unreadable_records": n_skip, "load_s": round(load_s, 2), "run_s": round(run_s, 2),
                   "verify_s": round(verify_s, 2), "replay_s": round(replay_s, 2),
                   "replay_records_per_s": round(n_rec / replay_s), "all_tables_match": same,
                   "log_mb": round(os.path.getsize(log.path) / 1e6, 1)}
        print(json.dumps(summary, indent=1))
        out = os.path.join(HERE, "..", "..", "results")
        with open(os.path.join(out, "pg_replay.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        with open(os.path.join(out, "pg_replay.json"), "w") as f:
            json.dump(summary, f, indent=1)
        return summary
    finally:
        live.close()
        cluster.stop()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
