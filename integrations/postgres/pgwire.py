"""Minimal PostgreSQL client: simple query protocol over a Unix socket,
trust authentication, text results. Enough to drive the benchmark without
installing a driver.
"""

import socket
import struct


class PgError(Exception):
    pass


class Conn:
    def __init__(self, sockdir="/tmp/pgsock", port=5433, user="pg", database="bench"):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(f"{sockdir}/.s.PGSQL.{port}")
        body = struct.pack(">I", 196608) + b"".join(
            k.encode() + b"\0" + v.encode() + b"\0" for k, v in
            (("user", user), ("database", database))) + b"\0"
        self.s.sendall(struct.pack(">I", len(body) + 4) + body)
        self._buf = b""
        while True:
            t, payload = self._msg()
            if t == b"R" and struct.unpack(">I", payload[:4])[0] != 0:
                raise PgError("only trust authentication is supported")
            if t == b"E":
                raise PgError(_err(payload))
            if t == b"Z":
                break

    def _read(self, n):
        while len(self._buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise PgError("server closed the connection")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _msg(self):
        head = self._read(5)
        n = struct.unpack(">I", head[1:5])[0]
        return head[:1], self._read(n - 4)

    def query(self, sql):
        """Run one or more statements; return the rows of the last result
        that had any (list of tuples of str/None)."""
        body = sql.encode() + b"\0"
        self.s.sendall(b"Q" + struct.pack(">I", len(body) + 4) + body)
        rows, last, err = [], [], None
        while True:
            t, p = self._msg()
            if t == b"D":
                n = struct.unpack(">H", p[:2])[0]
                off, row = 2, []
                for _ in range(n):
                    ln = struct.unpack(">i", p[off:off + 4])[0]
                    off += 4
                    if ln < 0:
                        row.append(None)
                    else:
                        row.append(p[off:off + ln].decode())
                        off += ln
                rows.append(tuple(row))
            elif t == b"C":
                if rows:
                    last = rows
                rows = []
            elif t == b"E":
                err = _err(p)
            elif t == b"Z":
                if err:
                    raise PgError(err)
                return last

    def close(self):
        try:
            self.s.sendall(b"X" + struct.pack(">I", 4))
        finally:
            self.s.close()


def _err(p):
    fields = dict((f[:1], f[1:]) for f in p.split(b"\0") if f)
    return (fields.get(b"M") or b"error").decode()


def lit(v):
    """SQL literal for an int/float/str/None."""
    if v is None:
        return "NULL"
    if isinstance(v, (int, float)):
        return repr(v)
    return "'" + str(v).replace("'", "''") + "'"
