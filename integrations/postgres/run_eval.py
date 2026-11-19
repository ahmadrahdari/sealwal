"""End-to-end experiments on PostgreSQL. Writes ../../results/pg_*.csv.

    python integrations/postgres/run_eval.py [matrix sweep erase nodekill]
"""

import csv
import os
import statistics
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tpcc  # noqa: E402

OUT = os.path.join(HERE, "..", "..", "results")


def save(name, rows):
    with open(os.path.join(OUT, name), "w", newline="") as f:
        names = []
        for r in rows:
            names += [k for k in r if k not in names]
        w = csv.DictWriter(f, fieldnames=names)
        w.writeheader()
        w.writerows(rows)


def median_run(cfg, workload, clients, seconds, reps, port):
    runs = [tpcc.run(cfg, workload, clients, seconds, base_port=port + 100 * r, seed=r + 1) for r in range(reps)]
    keys = ["tps", "p50_ms", "p99_ms", "p999_ms"]
    out = dict(runs[0])
    for k in keys:
        out[k] = round(statistics.median(r[k] for r in runs), 3)
        out[k + "_min"] = min(r[k] for r in runs)
        out[k + "_max"] = max(r[k] for r in runs)
    out["ran_out"] = any(r["ran_out"] for r in runs)
    return out


def matrix(seconds=10, reps=3, clients=16, workloads=("tpcc", "ycsb-a", "ycsb-b"), name="pg_matrix.csv"):
    rows = []
    port = 32000
    for workload in workloads:
        for cfg in ("pg-sync", "plain-log", "classical", "sealwal-mldsa", "sealwal", "sealwal-k4"):
            r = median_run(cfg, workload, clients, seconds, reps, port)
            port += 400
            rows.append(r)
            print("matrix", {k: r[k] for k in ("config", "workload", "tps", "p50_ms", "p99_ms", "p999_ms")},
                  flush=True)
            save(name, rows)


def sweep(seconds=8):
    rows, port = [], 40000
    for cfg in ("pg-sync", "plain-log", "sealwal"):
        for clients in (1, 4, 8, 16, 32):
            r = tpcc.run(cfg, "tpcc", clients, seconds, base_port=port)
            port += 100
            rows.append(r)
            print("sweep", cfg, clients, r["tps"], r["p99_ms"], flush=True)
            save("pg_sweep.csv", rows)


def erase_interference(seconds=10, clients=16):
    """p99 with and without a subject being erased every 50 ms (idle subjects,
    so live sessions keep working), on a key store holding 1M subjects."""
    rows, port = [], 44000
    for shredding in (False, True):
        state = {}
        stop = threading.Event()
        shred_lat = []
        orig_run = tpcc.run

        def run_with_shredder():
            return orig_run("sealwal", "tpcc", clients, seconds, base_port=port, out=state)

        if shredding:
            # wrap Engine creation: preload and start shredding once the key store exists
            orig_engine = tpcc.Engine

            class ShreddingEngine(orig_engine):
                def __init__(self, *a, **k):
                    super().__init__(*a, **k)
                    self.keys.bulk_load(1_000_000)
                    handles = [self.keys.subject("https://idle", "x", f"idle{i}")[0] for i in range(2000)]

                    def loop():
                        i = 0
                        while not stop.wait(0.05) and i < len(handles):
                            t = time.perf_counter()
                            self.keys.shred(handles[i])
                            shred_lat.append(time.perf_counter() - t)
                            i += 1
                    threading.Thread(target=loop, daemon=True).start()
            tpcc.Engine = ShreddingEngine
            try:
                r = run_with_shredder()
            finally:
                tpcc.Engine = orig_engine
                stop.set()
        else:
            orig_engine = tpcc.Engine

            class PreloadedEngine(orig_engine):
                def __init__(self, *a, **k):
                    super().__init__(*a, **k)
                    self.keys.bulk_load(1_000_000)
            tpcc.Engine = PreloadedEngine
            try:
                r = run_with_shredder()
            finally:
                tpcc.Engine = orig_engine
        r["shredding"] = shredding
        r["shreds"] = len(shred_lat)
        r["shred_ms_p50"] = round(statistics.median(shred_lat) * 1e3, 2) if shred_lat else None
        r["shred_ms_p99"] = round(sorted(shred_lat)[int(0.99 * len(shred_lat))] * 1e3, 2) if shred_lat else None
        rows.append({k: r.get(k) for k in ("shredding", "tps", "p50_ms", "p99_ms", "p999_ms", "shreds",
                                            "shred_ms_p50", "shred_ms_p99")})
        print("erase", rows[-1], flush=True)
        port += 200
    save("pg_erase.csv", rows)


def node_kill(seconds=12, clients=16, kill_at=5.0):
    """Throughput timeline when one of three log nodes dies mid-run."""
    import tpcc as t
    orig_cluster = t.Cluster
    timeline = []

    class KillingCluster(orig_cluster):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            threading.Timer(kill_at + 3.0, self.procs[0].kill).start()   # +setup time
    t.Cluster = KillingCluster
    orig_submit = t.GroupCommitter.submit
    marks = []

    def submit(self, payload):
        lsn = orig_submit(self, payload)
        marks.append(time.perf_counter())
        return lsn
    t.GroupCommitter.submit = submit
    try:
        r = t.run("sealwal", "tpcc", clients, seconds, base_port=46000)
    finally:
        t.Cluster = orig_cluster
        t.GroupCommitter.submit = orig_submit
    if marks:
        t0 = marks[0]
        buckets = {}
        for m in marks:
            b = int((m - t0) / 0.5)
            buckets[b] = buckets.get(b, 0) + 1
        for b in sorted(buckets):
            timeline.append({"t": b * 0.5, "tps": buckets[b] * 2})
    save("pg_nodekill.csv", timeline)
    print("nodekill", r["tps"], len(timeline), flush=True)


if __name__ == "__main__":
    todo = sys.argv[1:] or ["matrix", "sweep", "erase", "nodekill"]
    for name in todo:
        {"matrix": matrix, "sweep": sweep, "erase": erase_interference, "nodekill": node_kill}[name]()
