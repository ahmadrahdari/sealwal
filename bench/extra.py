"""Extra experiments (the ones reviewers ask for). Writes results/*.csv.

  python bench/extra.py

  ksweep   bounded async signing: throughput and window for K = 0..inf
  rollover HSS sign latency with and without background epoch prefetch
  faults   random crash points (truncation + torn bytes), check recovery
  keys     erasure cost vs size of the subject key store
  ycsb     YCSB-A-like workload on the key-value example (50/50 r/w, zipf)
"""

import csv
import json
import os
import random
import shutil
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealwal import GroupCommitter, KeyStore, SealedLog, make_signer, verify  # noqa: E402
from sealwal import lms  # noqa: E402
from sealwal.verify import scan  # noqa: E402
from sealwal import format as fmt  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")
PAYLOAD = os.urandom(256)


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def save(name, rows):
    with open(os.path.join(OUT, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def ksweep(tmp, secs=1.5, reps=3, clients=16):
    s = make_signer("ml-dsa-65")
    rows = []
    for k in [0, 1, 2, 4, 8, None]:
        runs = []
        for _ in range(reps):
            path = os.path.join(tmp, "k.wal")
            if os.path.exists(path):
                os.remove(path)
            log = SealedLog.create(path, s, sync="fdatasync", async_sign=True, max_unsigned=k,
                                   track_auth_lag=True)
            gc = GroupCommitter(log)
            lat = [[] for _ in range(clients)]
            stop = threading.Event()

            def client(i):
                while not stop.is_set():
                    t = time.perf_counter()
                    gc.submit(PAYLOAD)
                    lat[i].append(time.perf_counter() - t)

            ts = [threading.Thread(target=client, args=(i,)) for i in range(clients)]
            t0 = time.perf_counter()
            for t in ts:
                t.start()
            time.sleep(secs)
            stop.set()
            for t in ts:
                t.join()
            took = time.perf_counter() - t0
            gc.close()
            log.close()
            allv = [x for xs in lat for x in xs]
            runs.append((len(allv) / took, pct(allv, .5) * 1e6, pct(log.auth_lag, .99) * 1e3))
        rows.append({"K": "inf" if k is None else k,
                     "rps": round(statistics.median(r[0] for r in runs)),
                     "p50_us": round(statistics.median(r[1] for r in runs), 1),
                     "window_p99_ms": round(statistics.median(r[2] for r in runs), 2)})
        print("ksweep", rows[-1], flush=True)
    save("ksweep.csv", rows)


def rollover(tmp, n=6000):
    """Sign n messages through 5+ epoch changes (1024 signatures per epoch),
    once back to back and once paced at 5,000 signatures/s, which is about
    the commit rate of the inline-HSS log. Prefetch can only hide the 76 ms
    epoch keygen if an epoch lasts longer than that."""
    rows = []
    for rate in (None, 5000):
        for prefetch in (True, False):
            k = lms.EpochHss(os.path.join(tmp, f"roll-{prefetch}-{rate}.json"), create=True,
                             prefetch=prefetch)
            time.sleep(0.2)
            lat = []
            nxt = time.perf_counter()
            for i in range(n):
                if rate:
                    nxt += 1 / rate
                    while time.perf_counter() < nxt:
                        pass
                t = time.perf_counter()
                k.sign(b"m%d" % i)
                lat.append(time.perf_counter() - t)
            k.close()
            rows.append({"rate": rate or "max", "prefetch": prefetch, "signatures": n,
                         "epochs": len(k.epochs_used),
                         "p50_us": round(pct(lat, .5) * 1e6, 1),
                         "p99_us": round(pct(lat, .99) * 1e6, 1),
                         "p999_us": round(pct(lat, .999) * 1e6, 1),
                         "max_ms": round(max(lat) * 1e3, 2)})
            print("rollover", rows[-1], flush=True)
    save("rollover.csv", rows)


def faults(tmp, trials=300):
    """Build a log, then crash it at random byte offsets (plus random garbage
    in the torn part) and check that recovery keeps exactly the records
    whose seal survived, verifies, and can continue."""
    rnd = random.Random(1)
    rows = []
    for alg in ("ed25519", "lms-hss"):
        s = make_signer(alg)
        base = os.path.join(tmp, f"f-{alg}.wal")
        log = SealedLog.create(base, s, sync="none", async_sign=(alg == "ed25519"))
        for i in range(400):
            log.append(b"rec-%d" % i)
            if rnd.random() < 0.3:
                log.commit()
        log.close()
        seal_ends = [(fmt.parse_seal(b).last_lsn, e) for _, t, b, e in scan(base).frames if t == fmt.SEAL]
        size = os.path.getsize(base)
        violations = 0
        epochs = set()
        for _ in range(trials):
            cut = rnd.randint(seal_ends[0][1] - 20, size)
            p = os.path.join(tmp, "crash.wal")
            shutil.copy(base, p)
            with open(p, "r+b") as f:
                f.truncate(cut)
                f.seek(0, 2)
                f.write(os.urandom(rnd.randint(0, 30)))       # torn garbage
            expect = max([lsn for lsn, end in seal_ends if end <= cut], default=0)
            try:
                s2 = make_signer(alg, s.private_bytes) if alg == "lms-hss" else s
                rlog = SealedLog.open(p, s2, sync="none")
                got = rlog.committed_lsn
                rlog.append(b"after")
                rlog.close()
                rep = verify(p, s.public_bytes)
                ok = rep.ok and got == expect and rep.committed_lsn == expect + 1
                if alg == "lms-hss":
                    with open(s.private_bytes.decode()) as f:
                        epochs.add(json.load(f)["next_epoch"])
            except Exception:
                ok = False
            violations += not ok
        # single-byte damage anywhere before the last frame must be reported,
        # never truncated away or accepted
        last_start = scan(base).frames[-1][0]
        missed = 0
        for _ in range(trials):
            p = os.path.join(tmp, "flip.wal")
            shutil.copy(base, p)
            pos = rnd.randrange(0, last_start)
            with open(p, "r+b") as f:
                f.seek(pos)
                b = f.read(1)
                f.seek(pos)
                f.write(bytes([b[0] ^ (1 << rnd.randrange(8))]))
            try:
                s2 = make_signer(alg, s.private_bytes) if alg == "lms-hss" else s
                SealedLog.open(p, s2, sync="none").close()
                missed += 1
            except Exception:
                pass
        rows.append({"alg": alg, "crash_trials": trials, "crash_violations": violations,
                     "flip_trials": trials, "flips_missed": missed,
                     "distinct_epochs": len(epochs) if alg == "lms-hss" else ""})
        print("faults", rows[-1], flush=True)
    save("faults.csv", rows)


def keys(tmp):
    rows = []
    for n in (1_000, 10_000, 100_000, 1_000_000):
        ks = KeyStore(os.path.join(tmp, f"ks-{n}.json"), create=True)
        ks._keys = {i: os.urandom(32) for i in range(1, n + 1)}
        ks._save()
        t = time.perf_counter()
        ks.shred(n // 2)
        took = time.perf_counter() - t
        rows.append({"subjects": n, "shred_ms": round(took * 1e3, 1),
                     "keystore_mb": round(os.path.getsize(ks.path) / 1e6, 1)})
        print("keys", rows[-1], flush=True)
    save("keystore.csv", rows)


def ycsb(tmp, secs=3.0, nkeys=1000, users=100):
    """50% reads (served from memory), 50% updates (logged), zipfian keys,
    8 client threads, group commit. Each key belongs to one user."""
    rows = []
    zipf_w = [1 / (i + 1) ** 0.99 for i in range(nkeys)]
    for name, alg, mode, private in [("unsigned, public", "none", {}, False),
                                     ("ML-DSA-65 inline, public", "ml-dsa-65", {}, False),
                                     ("ML-DSA-65 async K=1, private", "ml-dsa-65",
                                      {"async_sign": True, "max_unsigned": 1}, True),
                                     ("Epoch HSS inline, public", "lms-hss", {}, False),
                                     ("Epoch HSS inline, private", "lms-hss", {}, True)]:
        s = make_signer(alg)
        ks = None
        if private:
            ks = KeyStore(os.path.join(tmp, f"y-{name}.json".replace(" ", "_")), create=True)
            for u in range(1, users + 1):
                ks.add_subject(u)
        path = os.path.join(tmp, "ycsb.wal")
        if os.path.exists(path):
            os.remove(path)
        log = SealedLog.create(path, s, sync="fdatasync", keys=ks, **mode)
        gc = GroupCommitter(log)
        state = {}
        lock = threading.Lock()
        ops = [0] * 8
        stop = threading.Event()

        def client(i):
            r = random.Random(i)
            while not stop.is_set():
                key = r.choices(range(nkeys), zipf_w)[0]
                if r.random() < 0.5:
                    with lock:
                        state.get(key)
                else:
                    rec = json.dumps({"k": key, "v": r.random()}).encode()
                    subject = key % users + 1 if private else 0
                    lsn = log.append(rec, subject)
                    with gc._cv:
                        gc._cv.notify_all()
                        while gc._durable < lsn:
                            gc._cv.wait()
                    with lock:
                        state[key] = rec
                ops[i] += 1

        ts = [threading.Thread(target=client, args=(i,)) for i in range(8)]
        t0 = time.perf_counter()
        for t in ts:
            t.start()
        time.sleep(secs)
        stop.set()
        for t in ts:
            t.join()
        took = time.perf_counter() - t0
        gc.close()
        log.close()
        assert verify(path, s.public_bytes if alg != "none" else None, keys=ks).ok
        rows.append({"config": name, "ops_per_s": round(sum(ops) / took)})
        print("ycsb", rows[-1], flush=True)
    save("ycsb.csv", rows)


if __name__ == "__main__":
    todo = sys.argv[1:] or ["ksweep", "rollover", "faults", "keys", "ycsb"]
    with tempfile.TemporaryDirectory(dir=os.path.join(os.path.dirname(__file__), "..")) as tmp:
        for name in todo:
            globals()[name](tmp)
