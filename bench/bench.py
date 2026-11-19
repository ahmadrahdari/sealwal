"""Benchmarks for sealwal.

    python bench/bench.py            # full run, writes results/*.csv
    python bench/bench.py --quick    # smoke test

Experiment A, batch sweep: one thread appends B records of 256 bytes and
    commits, repeatedly. Measures commit latency (Merkle root + signature +
    write + fdatasync) and throughput for each signature scheme.
Experiment B, group commit: C client threads each submit records in a loop
    through GroupCommitter. Measures per-record latency as seen by the client
    and throughput, for inline signing vs. asynchronous signing.
Experiment C, verification and proofs: time to verify a 100k-record log,
    and inclusion-proof size.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealwal import GroupCommitter, SealedLog, make_signer, prove, verify  # noqa: E402

RESULTS = os.path.join(os.path.dirname(__file__), "..", "results")
PAYLOAD = os.urandom(256)


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def exp_batch(tmp, algs, batches, sync, seconds):
    rows = []
    for alg in algs:
        signer = make_signer(alg)
        for b in batches:
            path = os.path.join(tmp, f"a-{alg}-{b}.wal")
            log = SealedLog.create(path, signer, sync=sync)
            lat = []
            n = 0
            t_end = time.perf_counter() + seconds
            while time.perf_counter() < t_end or len(lat) < 20:
                for _ in range(b):
                    log.append(PAYLOAD)
                t = time.perf_counter()
                log.commit()
                lat.append(time.perf_counter() - t)
                n += b
            elapsed = sum(lat)
            log.close()
            size = os.path.getsize(path)
            rows.append(
                {
                    "alg": alg,
                    "batch": b,
                    "sync": sync,
                    "commits": len(lat),
                    "commit_p50_us": round(pct(lat, 0.5) * 1e6, 1),
                    "commit_p99_us": round(pct(lat, 0.99) * 1e6, 1),
                    "records_per_s": round(n / elapsed),
                    "bytes_per_record": round(size / n, 1),
                }
            )
            os.remove(path)
            print("A", rows[-1], flush=True)
    return rows


def exp_group(tmp, configs, clients_list, seconds):
    rows = []
    for alg, mode in configs:
        signer = make_signer(alg)
        for clients in clients_list:
            path = os.path.join(tmp, f"b-{alg}-{mode}-{clients}.wal")
            log = SealedLog.create(
                path, signer, sync="fdatasync", async_sign=(mode == "async"), track_auth_lag=True
            )
            gc = GroupCommitter(log)
            lats: list[list[float]] = [[] for _ in range(clients)]
            stop = threading.Event()

            def client(i):
                out = lats[i]
                while not stop.is_set():
                    t = time.perf_counter()
                    gc.submit(PAYLOAD)
                    out.append(time.perf_counter() - t)

            ts = [threading.Thread(target=client, args=(i,)) for i in range(clients)]
            t0 = time.perf_counter()
            for t in ts:
                t.start()
            time.sleep(seconds)
            stop.set()
            for t in ts:
                t.join()
            elapsed = time.perf_counter() - t0
            gc.close()
            log.close()
            rep = verify(path, signer.public_bytes if alg != "none" else None)
            assert rep.ok, rep.errors
            all_l = [x for xs in lats for x in xs]
            lag = log.auth_lag or [0.0]
            rows.append(
                {
                    "alg": alg,
                    "mode": mode,
                    "clients": clients,
                    "records": len(all_l),
                    "latency_p50_us": round(pct(all_l, 0.5) * 1e6, 1),
                    "latency_p99_us": round(pct(all_l, 0.99) * 1e6, 1),
                    "records_per_s": round(len(all_l) / elapsed),
                    "mean_batch": round(statistics.mean(gc.batches), 1),
                    "auth_window_p50_us": round(pct(lag, 0.5) * 1e6, 1),
                    "auth_window_p99_us": round(pct(lag, 0.99) * 1e6, 1),
                }
            )
            os.remove(path)
            print("B", rows[-1], flush=True)
    return rows


def exp_verify(tmp, algs, n, batch):
    rows = []
    for alg in algs:
        signer = make_signer(alg)
        path = os.path.join(tmp, f"c-{alg}.wal")
        log = SealedLog.create(path, signer, sync="none")
        for i in range(n):
            log.append(PAYLOAD)
            if (i + 1) % batch == 0:
                log.commit()
        log.close()
        t = time.perf_counter()
        rep = verify(path, signer.public_bytes if alg != "none" else None)
        dt = time.perf_counter() - t
        assert rep.ok
        proof = prove(path, n // 2)
        rows.append(
            {
                "alg": alg,
                "records": n,
                "batch": batch,
                "verify_s": round(dt, 3),
                "verify_records_per_s": round(n / dt),
                "proof_bytes_json": len(json.dumps(proof)),
                "proof_path_hashes": len(proof["audit_path"]),
            }
        )
        os.remove(path)
        print("C", rows[-1], flush=True)
    return rows


def save(name, rows):
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    secs = 0.3 if a.quick else 2.0
    algs = ["none", "ed25519", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]
    with tempfile.TemporaryDirectory(dir=os.path.join(os.path.dirname(__file__), "..")) as tmp:
        save("batch_sweep.csv", exp_batch(tmp, algs, [1, 4, 16, 64, 256], "fdatasync", secs))
        save(
            "group_commit.csv",
            exp_group(
                tmp,
                [("none", "inline"), ("ed25519", "inline"), ("ml-dsa-65", "inline"), ("ml-dsa-65", "async")],
                [1, 4, 16, 64],
                secs,
            ),
        )
        save("verify.csv", exp_verify(tmp, ["none", "ed25519", "ml-dsa-65"], 20_000 if a.quick else 100_000, 64))
    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpus": os.cpu_count(),
    }
    with open(os.path.join(RESULTS, "environment.json"), "w") as f:
        json.dump(env, f, indent=2)
    print(env)


if __name__ == "__main__":
    main()
