"""Command line interface.

    python -m sealwal keygen  --alg ml-dsa-65 --out key        # key.priv, key.pub
    python -m sealwal demo    --alg ml-dsa-65 --key key --log demo.wal -n 1000
    python -m sealwal verify  demo.wal --pubkey key.pub [--anchor 12:<hex>]
    python -m sealwal prove   demo.wal --lsn 42 > proof.json
    python -m sealwal check   proof.json --pubkey key.pub
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from . import ALG_IDS, SealedLog, check_proof, make_signer, prove, verify


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sealwal")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate a signing key pair")
    k.add_argument("--alg", default="ml-dsa-65", choices=sorted(ALG_IDS))
    k.add_argument("--out", required=True, help="writes OUT.priv and OUT.pub")

    d = sub.add_parser("demo", help="write a log of N synthetic records")
    d.add_argument("--alg", default="ml-dsa-65", choices=sorted(ALG_IDS))
    d.add_argument("--key", help="key prefix from keygen (default: fresh key)")
    d.add_argument("--log", required=True)
    d.add_argument("-n", type=int, default=1000)
    d.add_argument("--batch", type=int, default=50)

    v = sub.add_parser("verify", help="verify a log file")
    v.add_argument("log")
    v.add_argument("--pubkey", help="pinned public key file")
    v.add_argument("--trust-header-key", action="store_true")
    v.add_argument("--anchor", help="SEAL_NO:DIGEST_HEX recorded out of band")

    pr = sub.add_parser("prove", help="print an inclusion proof for one record")
    pr.add_argument("log")
    pr.add_argument("--lsn", type=int, required=True)

    c = sub.add_parser("check", help="check an inclusion proof")
    c.add_argument("proof")
    c.add_argument("--pubkey", required=True)

    a = p.parse_args(argv)

    if a.cmd == "keygen":
        s = make_signer(a.alg)
        with open(a.out + ".priv", "wb") as f:
            f.write(a.alg.encode() + b"\n" + s.private_bytes)
        with open(a.out + ".pub", "wb") as f:
            f.write(s.public_bytes)
        print(f"wrote {a.out}.priv and {a.out}.pub ({a.alg}, public key {len(s.public_bytes)} bytes)")
        return 0

    if a.cmd == "demo":
        if a.key:
            alg, priv = _read(a.key + ".priv").split(b"\n", 1)
            s = make_signer(alg.decode(), priv)
        else:
            s = make_signer(a.alg)
        with SealedLog.create(a.log, s) as log:
            for i in range(a.n):
                log.append(json.dumps({"op": "put", "key": f"k{i}", "value": i}).encode())
                if (i + 1) % a.batch == 0:
                    log.commit()
        print(f"wrote {a.n} records to {a.log}")
        return 0

    if a.cmd == "verify":
        anchor = None
        if a.anchor:
            no, hx = a.anchor.split(":")
            anchor = (int(no), bytes.fromhex(hx))
        key = _read(a.pubkey) if a.pubkey else None
        rep = verify(a.log, key, trust_header_key=a.trust_header_key, anchor=anchor)
        print(json.dumps(asdict(rep), indent=2))
        return 0 if rep.ok else 1

    if a.cmd == "prove":
        print(json.dumps(prove(a.log, a.lsn), indent=2))
        return 0

    if a.cmd == "check":
        with open(a.proof) as f:
            ok, why = check_proof(json.load(f), _read(a.pubkey))
        print(("OK: " if ok else "FAIL: ") + why)
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
