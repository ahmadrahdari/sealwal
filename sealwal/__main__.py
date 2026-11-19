"""Command line.

  python -m sealwal keygen --alg lms-hss --out key       (key.priv, key.pub)
  python -m sealwal demo   --key key --log demo.wal -n 1000
  python -m sealwal verify demo.wal --pubkey key.pub [--anchor 12:<hex>]
  python -m sealwal prove  demo.wal --lsn 42 > proof.json
  python -m sealwal check  proof.json --pubkey key.pub
  python -m sealwal consistency demo.wal --old 3 > cons.json
  python -m sealwal check-consistency cons.json --pubkey key.pub --old-digest <hex>
"""

import argparse
import json
import sys
from dataclasses import asdict

from . import (ALG_IDS, SealedLog, check_consistency, check_proof, make_signer, prove,
               prove_consistency, verify)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _load_signer(prefix):
    raw = _read(prefix + ".priv")
    if raw.startswith(b"{"):                      # lms-hss key file (json)
        return make_signer("lms-hss", (prefix + ".priv").encode())
    alg, priv = raw.split(b"\n", 1)
    return make_signer(alg.decode(), priv)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sealwal")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen")
    p.add_argument("--alg", default="ml-dsa-65", choices=sorted(ALG_IDS))
    p.add_argument("--out", required=True)

    p = sub.add_parser("demo")
    p.add_argument("--alg", default="ml-dsa-65", choices=sorted(ALG_IDS))
    p.add_argument("--key")
    p.add_argument("--log", required=True)
    p.add_argument("-n", type=int, default=1000)
    p.add_argument("--batch", type=int, default=50)

    p = sub.add_parser("verify")
    p.add_argument("log")
    p.add_argument("--pubkey")
    p.add_argument("--trust-header-key", action="store_true")
    p.add_argument("--anchor", help="SEAL_NO:DIGEST_HEX")

    p = sub.add_parser("prove")
    p.add_argument("log")
    p.add_argument("--lsn", type=int, required=True)

    p = sub.add_parser("check")
    p.add_argument("proof")
    p.add_argument("--pubkey", required=True)

    p = sub.add_parser("consistency")
    p.add_argument("log")
    p.add_argument("--old", type=int, required=True)
    p.add_argument("--new", type=int)

    p = sub.add_parser("check-consistency")
    p.add_argument("proof")
    p.add_argument("--pubkey", required=True)
    p.add_argument("--old-digest")

    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        if a.alg == "lms-hss":
            from .lms import EpochHss
            k = EpochHss(a.out + ".priv", create=True)
            k.close()
            pub = k.public_key
            print(f"wrote {a.out}.priv (seed + epoch counter, don't restore it from a backup)")
        else:
            s = make_signer(a.alg)
            with open(a.out + ".priv", "wb") as f:
                f.write(a.alg.encode() + b"\n" + s.private_bytes)
            pub = s.public_bytes
        with open(a.out + ".pub", "wb") as f:
            f.write(pub)
        print(f"wrote {a.out}.pub ({len(pub)} bytes)")
        return 0

    if a.cmd == "demo":
        s = _load_signer(a.key) if a.key else make_signer(a.alg)
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
        rep = verify(a.log, _read(a.pubkey) if a.pubkey else None,
                     trust_header_key=a.trust_header_key, anchor=anchor)
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

    if a.cmd == "consistency":
        print(json.dumps(prove_consistency(a.log, a.old, a.new), indent=2))
        return 0

    if a.cmd == "check-consistency":
        with open(a.proof) as f:
            old = bytes.fromhex(a.old_digest) if a.old_digest else None
            ok, why = check_consistency(json.load(f), _read(a.pubkey), old)
        print(("OK: " if ok else "FAIL: ") + why)
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
