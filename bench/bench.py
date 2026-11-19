"""Benchmarks. Writes results/*.csv.

  python bench/bench.py           # everything, ~6 min
  python bench/bench.py --quick   # smoke test

  batch   one writer, B records of 256 B per commit, real fdatasync
  group   N client threads through GroupCommitter, real fdatasync
  flush   one writer, 1 record per commit, flush latency *emulated*
          (busy wait) to model fast remote log services
  verify  verification speed and proof sizes on a 100k-record log
  micro   raw sign/verify cost and signature sizes
  privacy cost of private (encrypted, salted) records vs public ones
  leak    how fast a receipt's neighbour can be brute-forced
  erase   erasure cost and audit speed with and without keys
  recover time to reopen a 100k-record log

Each configuration runs REPS times; summary files keep the median of the
per-run medians plus the min and max across runs.
"""

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

from sealwal import (GroupCommitter, KeyStore, SealedLog, make_signer, prove,  # noqa: E402
                     prove_consistency, verify)
from sealwal import merkle  # noqa: E402
from sealwal.privacy import ZERO_SALT, commit  # noqa: E402
from sealwal import format as fmt  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")
PAYLOAD = os.urandom(256)
REPS = 3
SIGNERS = {}


def signer(alg):
    # one key per algorithm for the whole run (LMS key setup isn't free)
    if alg not in SIGNERS:
        SIGNERS[alg] = make_signer(alg)
    return SIGNERS[alg]


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def mode_opts(mode):
    if mode == "inline":
        return {}
    if mode == "async":
        return {"async_sign": True}
    if mode.startswith("async-k"):
        return {"async_sign": True, "max_unsigned": int(mode[7:])}
    raise ValueError(mode)


KEYS = None


def keystore(tmp):
    global KEYS
    if KEYS is None:
        KEYS = KeyStore(os.path.join(tmp, "keys.json"), create=True)
        KEYS.add_subject(1)
    return KEYS


def run_writer(tmp, alg, batch, sync, secs, mode="inline", private=False):
    path = os.path.join(tmp, "w.wal")
    if os.path.exists(path):
        os.remove(path)
    keys = keystore(tmp) if private else None
    subject = 1 if private else 0
    log = SealedLog.create(path, signer(alg), sync=sync, keys=keys, **mode_opts(mode))
    lat, app, n = [], [], 0
    end = time.perf_counter() + secs
    while time.perf_counter() < end or len(lat) < 30:
        t0 = time.perf_counter()
        for _ in range(batch):
            log.append(PAYLOAD, subject)
        ta = time.perf_counter() - t0
        t = time.perf_counter()
        log.commit()
        lat.append(time.perf_counter() - t)
        app.append(ta)
        n += batch
    busy = sum(lat) + sum(app)
    log.close()
    size = os.path.getsize(path)
    return {"p50": pct(lat, .5) * 1e6, "p99": pct(lat, .99) * 1e6,
            "rps": n / busy, "bytes_per_rec": size / n}


def run_group(tmp, alg, mode, clients, secs):
    path = os.path.join(tmp, "g.wal")
    if os.path.exists(path):
        os.remove(path)
    log = SealedLog.create(path, signer(alg), sync="fdatasync", track_auth_lag=True,
                           **mode_opts(mode))
    gc = GroupCommitter(log)
    lats = [[] for _ in range(clients)]
    stop = threading.Event()

    def client(i):
        mine = lats[i]
        while not stop.is_set():
            t = time.perf_counter()
            gc.submit(PAYLOAD)
            mine.append(time.perf_counter() - t)

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
    rep = verify(path, signer(alg).public_bytes if alg != "none" else None)
    assert rep.ok, rep.errors
    allv = [x for xs in lats for x in xs]
    lag = log.auth_lag or [0.0]
    return {"p50": pct(allv, .5) * 1e6, "p99": pct(allv, .99) * 1e6, "rps": len(allv) / took,
            "batch": statistics.mean(gc.batches), "win_p50": pct(lag, .5) * 1e6,
            "win_p99": pct(lag, .99) * 1e6}


def repeat(fn, *args):
    runs = [fn(*args) for _ in range(REPS)]
    out = {}
    for k in runs[0]:
        vals = [r[k] for r in runs]
        out[k] = round(statistics.median(vals), 1)
        out[k + "_min"] = round(min(vals), 1)
        out[k + "_max"] = round(max(vals), 1)
    return out


def exp_privacy(tmp, secs):
    rows = []
    for alg in ["none", "ed25519", "lms-hss"]:
        for private in (False, True):
            for b in (1, 64):
                r = {"alg": alg, "private": private, "batch": b,
                     **repeat(run_writer, tmp, alg, b, "fdatasync", secs, "inline", private)}
                rows.append(r)
                print("privacy", alg, private, b, r["p50"], r["rps"], flush=True)
    save("privacy.csv", rows)


def exp_leak(tmp):
    # a receipt for record 1 carries record 2's leaf as its first sibling
    rows = []
    for private in (False, True):
        path = os.path.join(tmp, f"leak-{private}.wal")
        keys = KeyStore(os.path.join(tmp, f"leak-keys-{private}.json"), create=True)
        keys.add_subject(1)
        keys.add_subject(2)
        log = SealedLog.create(path, signer("ed25519"), sync="none", keys=keys)
        log.append(b'{"acct": 1, "balance": 52817}', 1 if private else 0)
        log.append(b'{"acct": 2, "balance": 734102}', 2 if private else 0)
        log.close()
        sib = bytes.fromhex(prove(path, 1, keys)["audit_path"][0])
        t = time.perf_counter()
        found = None
        for v in range(1_000_000):
            if merkle.leaf_hash(2, commit(ZERO_SALT, b'{"acct": 2, "balance": %d}' % v)) == sib:
                found = v
                break
        took = time.perf_counter() - t
        rows.append({"records": "private" if private else "public", "guesses": v + 1,
                     "seconds": round(took, 2), "recovered": found})
        print("leak", rows[-1], flush=True)
    save("leak.csv", rows)


def exp_erase(tmp, n=100_000, subjects=10_000):
    import random
    keys = KeyStore(os.path.join(tmp, "erase-keys.json"), create=True)
    for u in range(1, subjects + 1):
        keys._keys[u] = os.urandom(32)
    keys._save()
    s = signer("ed25519")
    path = os.path.join(tmp, "erase.wal")
    log = SealedLog.create(path, s, sync="none", keys=keys)
    rnd = random.Random(7)
    for i in range(n):
        log.append(PAYLOAD, rnd.randint(1, subjects))
        if (i + 1) % 64 == 0:
            log.commit()
    log.close()
    t = time.perf_counter()
    rep_nokeys = verify(path, s.public_bytes)
    t_nokeys = time.perf_counter() - t
    t = time.perf_counter()
    rep_keys = verify(path, s.public_bytes, keys=keys)
    t_keys = time.perf_counter() - t
    t = time.perf_counter()
    keys.shred(42)
    t_shred = time.perf_counter() - t
    t = time.perf_counter()
    rep_after = verify(path, s.public_bytes, keys=keys)
    t_after = time.perf_counter() - t
    assert rep_nokeys.ok and rep_keys.ok and rep_after.ok
    rows = [{"records": n, "subjects": subjects,
             "audit_no_keys_s": round(t_nokeys, 3), "verify_with_keys_s": round(t_keys, 3),
             "shred_ms": round(t_shred * 1000, 2), "verify_after_shred_s": round(t_after, 3),
             "erased_records": rep_after.erased_records}]
    print("erase", rows[0], flush=True)
    save("erase.csv", rows)


def exp_recover(tmp, n=100_000):
    rows = []
    for alg in ["ed25519", "lms-hss"]:
        s = signer(alg)
        path = os.path.join(tmp, f"rec-{alg}.wal")
        log = SealedLog.create(path, s, sync="none")
        for i in range(n):
            log.append(PAYLOAD)
            if (i + 1) % 64 == 0:
                log.commit()
        log.append(PAYLOAD)
        os.close(log._fd)                      # crash with an unsealed record
        if alg == "lms-hss":
            s = make_signer("lms-hss", s.private_bytes)   # new process, new epoch
        t = time.perf_counter()
        log = SealedLog.open(path, s, sync="none")
        took = time.perf_counter() - t
        log.close()
        rows.append({"alg": alg, "records": n, "reopen_s": round(took, 3)})
        print("recover", rows[-1], flush=True)
    save("recover.csv", rows)


def save(name, rows):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def exp_batch(tmp, secs):
    rows = []
    for alg in ["none", "ed25519", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
                "hybrid-ed25519-ml-dsa-65", "lms-hss"]:
        for b in [1, 8, 64, 256]:
            r = {"alg": alg, "batch": b, **repeat(run_writer, tmp, alg, b, "fdatasync", secs)}
            rows.append(r)
            print("batch", alg, b, r["p50"], r["rps"], flush=True)
    save("batch_sweep.csv", rows)


def exp_group(tmp, secs):
    rows = []
    for alg, mode in [("none", "inline"), ("ed25519", "inline"), ("ml-dsa-65", "inline"),
                      ("ml-dsa-65", "async"), ("ml-dsa-65", "async-k1"), ("lms-hss", "inline")]:
        for c in [1, 4, 16, 64]:
            r = {"alg": alg, "mode": mode, "clients": c, **repeat(run_group, tmp, alg, mode, c, secs)}
            rows.append(r)
            print("group", alg, mode, c, r["p50"], r["rps"], flush=True)
    save("group_commit.csv", rows)


def exp_flush(tmp, secs):
    rows = []
    for us in [10, 25, 50, 100, 200, 500]:
        for alg, mode in [("none", "inline"), ("ed25519", "inline"), ("ml-dsa-65", "inline"),
                          ("ml-dsa-65", "async"), ("lms-hss", "inline")]:
            r = {"flush_us": us, "alg": alg, "mode": mode,
                 **repeat(run_writer, tmp, alg, 1, f"emulate:{us}", secs, mode)}
            rows.append(r)
            print("flush", us, alg, mode, r["p50"], flush=True)
    save("flush_sweep.csv", rows)


def exp_verify(tmp, n):
    rows = []
    for alg in ["none", "ed25519", "ml-dsa-65", "lms-hss"]:
        s = signer(alg)
        path = os.path.join(tmp, f"v-{alg}.wal")
        log = SealedLog.create(path, s, sync="none")
        for i in range(n):
            log.append(PAYLOAD)
            if (i + 1) % 64 == 0:
                log.commit()
        log.close()
        key = s.public_bytes if alg != "none" else None
        t = time.perf_counter()
        rep = verify(path, key)
        took = time.perf_counter() - t
        assert rep.ok
        incl = prove(path, n // 2)
        cons = prove_consistency(path, 0)
        rows.append({"alg": alg, "records": n, "verify_s": round(took, 3),
                     "verify_rps": round(n / took),
                     "incl_hashes": len(incl["audit_path"]),
                     "incl_bytes": len(json.dumps(incl)),
                     "sig_bytes": len(bytes.fromhex(incl["signature"])),
                     "cons_hashes": len(cons["proof"])})
        print("verify", rows[-1], flush=True)
    save("verify.csv", rows)


def exp_micro():
    from sealwal import lms
    rows = []
    msg = fmt.signed_message(os.urandom(32))
    for alg in ["ed25519", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "lms-hss"]:
        s = signer(alg)
        from sealwal.signers import verify_signature
        sl, vl = [], []
        for _ in range(500):
            t = time.perf_counter()
            sig = s.sign(msg)
            sl.append(time.perf_counter() - t)
            t = time.perf_counter()
            assert verify_signature(alg, s.public_bytes, sig, msg)
            vl.append(time.perf_counter() - t)
        rows.append({"alg": alg, "sign_p50_us": round(pct(sl, .5) * 1e6, 1),
                     "sign_p99_us": round(pct(sl, .99) * 1e6, 1),
                     "verify_p50_us": round(pct(vl, .5) * 1e6, 1),
                     "sig_bytes": len(sig), "pk_bytes": len(s.public_bytes)})
        print("micro", rows[-1], flush=True)
    d = tempfile.mkdtemp()
    t = time.perf_counter()
    lms.LmsTree(os.urandom(16), os.urandom(32), 10)
    rows.append({"alg": "lms epoch tree keygen (h=10, 1024 leaves)",
                 "sign_p50_us": round((time.perf_counter() - t) * 1e6, 1),
                 "sign_p99_us": "", "verify_p50_us": "", "sig_bytes": "", "pk_bytes": ""})
    save("micro.csv", rows)


def main():
    global REPS
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    secs = 0.2 if a.quick else 1.0
    if a.quick:
        REPS = 1
    todo = a.only or ["micro", "batch", "group", "flush", "verify", "privacy", "leak", "erase",
                      "recover"]
    with tempfile.TemporaryDirectory(dir=os.path.join(os.path.dirname(__file__), "..")) as tmp:
        if "micro" in todo:
            exp_micro()
        if "batch" in todo:
            exp_batch(tmp, secs)
        if "group" in todo:
            exp_group(tmp, secs * 1.5)
        if "flush" in todo:
            exp_flush(tmp, secs)
        if "verify" in todo:
            exp_verify(tmp, 20_000 if a.quick else 100_000)
        if "privacy" in todo:
            exp_privacy(tmp, secs)
        if "leak" in todo:
            exp_leak(tmp)
        if "erase" in todo:
            exp_erase(tmp, 20_000 if a.quick else 100_000)
        if "recover" in todo:
            exp_recover(tmp, 20_000 if a.quick else 100_000)
    with open(os.path.join(OUT, "environment.json"), "w") as f:
        json.dump({"python": platform.python_version(), "platform": platform.platform(),
                   "cpus": os.cpu_count(), "reps": REPS}, f, indent=2)


if __name__ == "__main__":
    main()
