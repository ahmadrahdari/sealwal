"""A tiny key-value store whose write-ahead log is a sealwal log.

Run:  python examples/kvstore.py

It writes some keys, "crashes" in the middle of a batch, recovers by
replaying the verified log, then shows that an edit to the log file made
while the store was down is refused on restart.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealwal import CorruptLogError, SealedLog, make_signer  # noqa: E402
from sealwal import format as fmt  # noqa: E402
from sealwal.verify import scan  # noqa: E402


class KVStore:
    def __init__(self, path: str, signer):
        self.data: dict[str, str] = {}
        if os.path.exists(path):
            self.log = SealedLog.open(path, signer)  # verifies + truncates the torn tail
            self._replay()
        else:
            self.log = SealedLog.create(path, signer)

    def _replay(self) -> None:
        committed = self.log.committed_lsn
        for _off, ftype, body, _end in scan(self.log.path).frames:
            if ftype != fmt.DATA:
                continue
            lsn, payload = fmt.parse_data(body)
            if lsn > committed:
                break
            op = json.loads(payload)
            if op["op"] == "put":
                self.data[op["k"]] = op["v"]
            else:
                self.data.pop(op["k"], None)

    def put(self, k: str, v: str) -> None:
        self.log.append(json.dumps({"op": "put", "k": k, "v": v}).encode())
        self.data[k] = v

    def delete(self, k: str) -> None:
        self.log.append(json.dumps({"op": "del", "k": k}).encode())
        self.data.pop(k, None)

    def commit(self) -> None:
        self.log.commit()

    def close(self) -> None:
        self.log.close()


def main() -> None:
    d = tempfile.mkdtemp()
    path = os.path.join(d, "kv.wal")
    signer = make_signer("ml-dsa-65")

    kv = KVStore(path, signer)
    kv.put("alice", "100")
    kv.put("bob", "50")
    kv.commit()
    kv.put("alice", "70")
    kv.put("carol", "30")
    kv.commit()
    kv.put("bob", "999")  # appended but never committed...
    os.close(kv.log._fd)  # ...because we crash here
    print("before crash (in memory):", kv.data)

    kv = KVStore(path, signer)
    print("after recovery:          ", kv.data)
    kv.close()

    # Someone with access to the storage edits alice's balance while the
    # store is down, and even fixes up the frame checksum.
    off, ftype, body, end = next(
        f for f in scan(path).frames if f[1] == fmt.DATA and b'"70"' in f[2]
    )
    lsn, payload = fmt.parse_data(body)
    evil = struct.pack(">Q", lsn) + payload.replace(b'"70"', b'"7e6"')
    head = struct.pack(">BI", ftype, len(evil))
    with open(path, "rb") as f:
        buf = bytearray(f.read())
    buf[off:end] = head + evil + struct.pack(">I", zlib.crc32(head + evil))
    with open(path, "wb") as f:
        f.write(buf)
    try:
        KVStore(path, signer)
    except CorruptLogError as e:
        print("tampered log refused:    ", e)


if __name__ == "__main__":
    main()
