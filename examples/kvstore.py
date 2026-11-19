"""A small key-value store on top of sealwal.

    python examples/kvstore.py

Each user's writes are private records of that user. The script writes a
few keys, crashes in the middle of a batch, recovers, then erases one user
(GDPR style) and shows that the log still verifies, the other users' data is
still there, and nobody can read the erased user's records any more.
Finally it edits the log behind the store's back and gets caught.
"""

import json
import os
import struct
import sys
import tempfile
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealwal import CorruptLogError, KeyStore, SealedLog, make_signer, read_records, verify  # noqa
from sealwal import format as fmt  # noqa
from sealwal.verify import scan  # noqa

USERS = {"alice": 1, "bob": 2, "carol": 3}


class KV:
    def __init__(self, path, signer, keys):
        self.keys = keys
        self.data = {}
        if os.path.exists(path):
            self.log = SealedLog.open(path, signer, keys=keys)
            for _, subject, payload in read_records(path, keys):
                if payload is not None:          # None = erased user
                    op = json.loads(payload)
                    self.data[op["k"]] = op["v"]
        else:
            self.log = SealedLog.create(path, signer, keys=keys)

    def put(self, user, k, v):
        self.log.append(json.dumps({"k": k, "v": v}).encode(), subject=USERS[user])
        self.data[k] = v

    def commit(self):
        self.log.commit()

    def close(self):
        self.log.close()


def main():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "kv.wal")
    signer = make_signer("lms-hss")
    keys = KeyStore(os.path.join(d, "keys.json"), create=True)
    for uid in USERS.values():
        keys.add_subject(uid)

    kv = KV(path, signer, keys)
    kv.put("alice", "alice:balance", 100)
    kv.put("bob", "bob:balance", 50)
    kv.commit()
    kv.put("alice", "alice:balance", 70)
    kv.put("carol", "carol:balance", 30)
    kv.commit()
    kv.put("bob", "bob:balance", 999)            # never committed...
    os.close(kv.log._fd)                         # ...because we crash here
    print("before crash :", kv.data)

    kv = KV(path, signer, keys)
    print("recovered    :", kv.data)
    kv.close()

    keys.shred(USERS["bob"])                     # bob asks to be forgotten
    rep = verify(path, signer.public_bytes, keys=keys)
    print("after erasing bob: log ok =", rep.ok, "| erased records =", rep.erased_records)
    print("store now    :", KV(path, signer, keys).data)
    rep = verify(path, signer.public_bytes)      # auditor, no keys at all
    print("auditor without keys: ok =", rep.ok, "| private records seen =", rep.private_records)

    # someone with access to the file swaps alice's ciphertext for an
    # older one of hers and fixes the CRC
    fr = scan(path).frames
    data = [f for f in fr if f[1] == fmt.DATA]
    off, ftype, _, end = data[2][0], data[2][1], data[2][2], data[2][3]
    lsn, subj, c, _ = fmt.parse_data(data[2][2])
    old_body = fmt.parse_data(data[0][2])[3]
    body = fmt.data_body(lsn, subj, c, old_body)
    head = struct.pack(">BI", ftype, len(body))
    with open(path, "rb") as f:
        buf = bytearray(f.read())
    buf[off:end] = head + body + struct.pack(">I", zlib.crc32(head + body))
    with open(path, "wb") as f:
        f.write(buf)
    try:
        KV(path, signer, keys)
    except (CorruptLogError, ValueError) as e:
        print("tampered log refused:", e)


if __name__ == "__main__":
    main()
