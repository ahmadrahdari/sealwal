"""A small replicated log service, and witnesses over the network.

Log nodes are dumb on purpose: they append bytes at an offset, fdatasync,
and acknowledge. They never see a key and are not trusted; everything they
store is checked by whoever reads it (seals, signatures, CRCs). The writer
sends every commit to all nodes and returns once a quorum has it durable,
which is how cloud log services (Socrates' XLOG, BtrLog) commit.

Witnesses run in their own processes as well and answer cosign requests.

Wire format, both directions: u32 length | body. Bodies use provenance.pack.
"""

import os
import socket
import struct
import threading
import time

from .provenance import pack, unpack, u64

_LEN = struct.Struct(">I")
APPEND, READ, SIZE = 1, 2, 3


def _send(sock, body):
    sock.sendall(_LEN.pack(len(body)) + body)


def _recv(sock):
    head = _recv_exact(sock, 4)
    return _recv_exact(sock, _LEN.unpack(head)[0])


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


def _listen(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    return srv


def serve_node(path, port, ready=None, sync=True):
    """Run a log node (blocks). path: the node's copy of the log."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    srv = _listen(port)
    if ready is not None:
        ready.set()
    while True:
        conn, _ = srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=_node_conn, args=(conn, fd, sync), daemon=True).start()


def _node_conn(conn, fd, sync):
    try:
        while True:
            op, a, data = unpack(_recv(conn))
            op, a = u64(op), u64(a)
            if op == APPEND:
                os.pwrite(fd, data, a)
                if sync:
                    os.fdatasync(fd)
                _send(conn, pack(a + len(data)))
            elif op == READ:
                size = os.fstat(fd).st_size
                _send(conn, pack(os.pread(fd, max(0, size - a), a)))
            elif op == SIZE:
                _send(conn, pack(os.fstat(fd).st_size))
    except (ConnectionError, OSError):
        conn.close()


class QuorumError(Exception):
    pass


class QuorumSink:
    """Writer side. send(offset, data) queues bytes to every node in order;
    wait(end) blocks until `quorum` nodes have everything up to end durable."""

    def __init__(self, addrs, quorum=None):
        self.addrs = list(addrs)
        self.quorum = quorum or len(self.addrs) // 2 + 1
        self._socks = []
        self._acked = [0] * len(self.addrs)
        self._alive = [True] * len(self.addrs)
        self._cv = threading.Condition()
        for i, (host, port) in enumerate(self.addrs):
            s = socket.create_connection((host, port))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._socks.append(s)
            threading.Thread(target=self._reader, args=(i,), daemon=True).start()
        self._send_lock = threading.Lock()

    def _reader(self, i):
        try:
            while True:
                end = u64(unpack(_recv(self._socks[i]))[0])
                with self._cv:
                    self._acked[i] = max(self._acked[i], end)
                    self._cv.notify_all()
        except (ConnectionError, OSError):
            with self._cv:
                self._alive[i] = False
                self._cv.notify_all()

    def send(self, offset, data):
        msg = pack(APPEND, offset, data)
        with self._send_lock:
            for i, s in enumerate(self._socks):
                if not self._alive[i]:
                    continue
                try:
                    _send(s, msg)
                except OSError:
                    with self._cv:
                        self._alive[i] = False
        return offset + len(data)

    def wait(self, end, timeout=10.0):
        deadline = time.monotonic() + timeout
        with self._cv:
            while sum(1 for a in self._acked if a >= end) < self.quorum:
                if sum(self._alive) < self.quorum:
                    raise QuorumError(f"only {sum(self._alive)} of {len(self.addrs)} log nodes left")
                left = deadline - time.monotonic()
                if left <= 0:
                    raise QuorumError("timed out waiting for a quorum")
                self._cv.wait(left)

    def live_nodes(self):
        with self._cv:
            return sum(self._alive)

    def close(self):
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass


def read_node(addr):
    """Fetch a node's whole copy (recovery, repair, audits)."""
    s = socket.create_connection(addr)
    try:
        _send(s, pack(READ, 0, b""))
        return unpack(_recv(s))[0]
    finally:
        s.close()


# ------------------------------------------------------------------ witnesses

def serve_witness(log_pk, log_alg, port, ready=None, pub_out=None):
    """Run a witness (blocks). pub_out: a multiprocessing queue that gets the
    witness's public key once it is up."""
    from .provenance import Witness, PolicyError
    w = Witness(log_pk, log_alg)
    if pub_out is not None:
        pub_out.put(w.public_bytes)
    srv = _listen(port)
    if ready is not None:
        ready.set()
    lock = threading.Lock()

    def handle(conn):
        try:
            while True:
                f = unpack(_recv(conn))
                seal_no, size, root, digest, t, first, prev, seal_sig, proof = f
                cp = {"seal_no": u64(seal_no), "size": u64(size), "root": root, "digest": digest,
                      "time": u64(t), "first": u64(first), "prev": prev}
                path = [proof[i:i + 32] for i in range(0, len(proof), 32)]
                try:
                    with lock:
                        sig = w.cosign(cp, path, seal_sig)
                    _send(conn, pack(b"ok", sig))
                except PolicyError as e:
                    _send(conn, pack(b"no", str(e)))
        except (ConnectionError, OSError):
            conn.close()

    while True:
        conn, _ = srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


class WitnessClient:
    def __init__(self, addrs):
        self.socks = [socket.create_connection(a) for a in addrs]
        for s in self.socks:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def cosign_all(self, cp, proofs, seal_sig):
        """proofs[i]: consistency proof from witness i's last checkpoint.
        Returns [(i, sig)] of the witnesses that agreed."""
        for s, proof in zip(self.socks, proofs):
            _send(s, pack(cp["seal_no"], cp["size"], cp["root"], cp["digest"], int(cp["time"]),
                          cp["first"], cp["prev"], seal_sig, b"".join(proof)))
        out = []
        for i, s in enumerate(self.socks):
            status, val = unpack(_recv(s))
            if status == b"ok":
                out.append((i, val))
        return out

    def close(self):
        for s in self.socks:
            s.close()
