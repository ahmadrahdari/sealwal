# sealwal

**Post-quantum write provenance for cloud write-ahead logs, from ordinary logins.**

Databases record *who* changed *what*, and some of that has to stay provable for
years: payment instructions, consents, audit trails. Today the "who" is a column
the application fills in, it sits in clear on whatever stores the log, and any
cryptographic evidence behind it (an RS256-signed ID token, a classical
signature on a digest) will be forgeable once quantum computers can break RSA.
NIST has fixed the dates: classical signatures are deprecated after 2030 and
disallowed after 2035.

sealwal is a write-ahead log that turns ordinary OpenID Connect logins into
**attribution receipts**: small proofs, checkable by anyone with a few public
keys, that a given record was requested by a given person. Receipts

* can't be produced by the database operator or by whoever stores the log,
* say nothing about other users, and the log itself holds no identities,
* stop working for a user once that user is erased, while everything else keeps verifying,
* stay valid after Q-day, **without any change to the identity provider or the cloud**.

## The idea: commit, then seal

A quantum attacker who has broken Google's RS256 key can mint any token Google
could have issued. What it can't change is *when* a token existed. So:

1. The client makes a fresh ML-DSA-44 session key and puts
   `nonce = H(vk | anchor_vk | t_max | r)` into a normal OIDC login. The signed ID token now vouches for the key.
2. The database logs a `BIND` record with only salted commitments:
   `c_id = H(rho, iss, aud, sub)` and `c_tok = H(rho, jwt, r)`, where
   `rho = HMAC(k_id, sid)` and `k_id` is that user's key in the key store.
3. Every transaction request is signed with the session key and logged as a
   `TXN` record: request commitment, signature, public effects in clear,
   private effects encrypted under `k_id`.
4. Group commits are sealed with the head of a history tree over the whole log
   and a hash-based (LMS/HSS) signature, replicated to a quorum of log nodes,
   and independent witnesses cosign checkpoints with the current time.

A classical binding counts as evidence only if a witnessed checkpoint dated
before a public **sunset** (say, end of 2030) covers it. After the sunset you
need a post-quantum token (ML-DSA JWTs, RFC 9964) or a *continuation*: a key
you registered in an earlier valid login signs the new session key. One login
before the sunset is enough forever. The paper also proves you can't do
better: with a classical-only IdP, nothing created after Q-day can prove who
someone is unless it builds on something sealed before.

The same commitment does three jobs. It freezes the token in time, it hides
the identity (the salt comes from `k_id`), and deleting `k_id` erases the user,
because nothing can open their commitments or decrypt their data anymore.

```
 client ──login(nonce)──> OpenID provider (unchanged, RS256)
   │  <──── ID token ────┘
   ├── ML-KEM envelope: jwt, vk, r ──> engine ── BIND(sid, vk, c_id, c_tok)
   └── signed requests ─────────────> engine ── TXN(sid, ctr, c_m, sig, pub, enc)
                                         │
                       group commit + seal (history tree, epoch HSS)
                                         │
                  log nodes (quorum, untrusted) ─> object storage
                                         │
                  witnesses cosign (size, root, time) ─> WITNESS record
```

## What's in the box

* `sealwal/log.py`: the WAL. Group commit, history-tree seals, inline or
  bounded-async signing (`max_unsigned=K`), crash recovery that tells a torn
  tail from tampering, replication through a quorum sink.
* `sealwal/lms.py` + `csrc/lmots.c`: **epoch-stateful HSS**. The top-level
  index of a two-level LMS key is a durable epoch counter, bumped (and fsynced)
  once per process start; inside an epoch the index lives in memory. A crash
  wastes leaves but never reuses one. `split_keyfile` gives each replica its
  own slice of epochs, so even a split brain can't reuse a one-time key. Lock
  timeouts and exhaustion fail closed, and the last epoch of every slice is kept
  for signing a key rotation.
* `sealwal/provenance.py`: sessions, binding, admission, records, erasure,
  witnesses and checkpoints, receipts and their verification, segment cut
  points for parallel audits.
* `sealwal/oidc.py`: issue and verify ID tokens (RS256 or ML-DSA-44), nonces.
* `sealwal/keystore.py`: subject keys in SQLite with `secure_delete`, the WAL
  truncated after each erasure so no copy of a key survives.
* `sealwal/replica.py`: log nodes and witnesses as separate processes over TCP.
* `integrations/postgres/`: PostgreSQL 16 integration where the log is the
  database. Stored procedures return after-images, the front end logs them and
  commits PostgreSQL asynchronously; `replay.py` rebuilds a database from the
  log alone.

## Quick start

Needs Python ≥ 3.10, `cryptography` ≥ 50 (ML-DSA, ML-KEM) and OpenSSL headers.

```bash
pip install -e .
make -C csrc                 # builds sealwal/_lmots.so
python -m pytest -q          # 145 tests
```

The protocol end to end, in-process:

```python
from sealwal import SealedLog, make_signer, oidc
from sealwal.keystore import KeyStore
from sealwal.provenance import (Engine, Session, Trust, Checkpointer, LocalWitnesses,
                                make_receipt, check_receipt)

idp = oidc.Provider(alg="RS256")                     # stands in for Google, Entra, ...
log = SealedLog.create("db.wal", make_signer("lms-hss"), keep_tree=True)
keys = KeyStore("subjects.db")
engine = Engine(log, keys, {idp.kid: idp.jwk}, aud="bank-app", sunset=1924988400)
wit = LocalWitnesses(3, log.signer.public_bytes, "lms-hss")   # normally other machines

s = Session()                                        # on the user's device
jwt = idp.issue("alice", "bank-app", s.nonce)        # ordinary OIDC login
s.bound(*engine.bind(s.bind_message(jwt)))
lsn = engine.admit(s.request(b"pay 100 EUR to bob"), private=b'{"balance": 900}')
log.commit()
Checkpointer(log, wit, 3, 2).run_once()              # witnessed checkpoint
log.commit()

opening = {"iss": idp.iss, "aud": "bank-app", "sub": "alice", "jwt": jwt, "r": s.r}
receipt = make_receipt("db.wal", lsn, keys, opening)
trust = Trust("lms-hss", log.signer.public_bytes, wit.keys, 2, {idp.kid: idp.jwk}, 1924988400)
print(check_receipt(receipt, trust))   # (True, 'record 3 was requested by alice at ...')
```

PostgreSQL (needs a local server on `/tmp/pgsock`, port 5433, trust auth):

```bash
python integrations/postgres/tpcc.py --load --config sealwal --seconds 10
python integrations/postgres/run_eval.py      # all configurations
python integrations/postgres/replay.py        # rebuild from the log, compare
```

## Threat model, briefly

The attacker may control the log nodes, the archive, the network, the engine
itself (and with it the log's signing key), any number of other users and
fewer than `t` witnesses, and at Q-day gets every classical secret in the
system. It still can't produce a receipt that attributes to an honest user a
request that user never made. Stated precisely: games with a Q-day event and
per-component compromise, proved with concrete bounds in the paper.

Not covered: an identity provider issuing tokens for its own users (true of
every OpenID system), the engine executing a request wrongly (users sign
requests, not effects), availability, and metadata. The log shows per-session
activity and timing, but no identities and no stable pseudonyms.

Assumptions you have to keep: the sunset comes before RSA-2048 falls, key
files of the HSS signer are never restored from backups, and backups of the
key store follow the keys' retention.

## Numbers

One shared VM, 2 vCPUs, an SSD with ~120 µs fdatasync. PostgreSQL 16, three
log nodes (quorum 2) and three witnesses all on the same two cores, 16 client
threads, median of three 10-second runs. "plain log" is the same architecture
with no signatures, commitments or encryption, so the gap to it is what sealwal
costs. Raw data is in `results/`.

| TPC-C-like (NewOrder + Payment) | tx/s | p99 ms |
|---|---|---|
| PostgreSQL, synchronous commit | 2,159 | 46 |
| plain log (no crypto) | 1,075 | 81 |
| classical (Ed25519 sessions and seals) | 886 | 96 |
| sealwal, ML-DSA-44 seals | 706 | 125 |
| **sealwal, epoch HSS seals** | **802** | **107** |

Being post-quantum costs 9.5% of throughput over the classical version of
the same design. The distance to stock PostgreSQL is the Python log service
sharing two cores and one disk with the database; it is already there without
any cryptography.

Other results:

* signing a request on the device: 404 µs (ML-DSA-44); verifying it on
  the server: 105 µs; an HSS seal signature: 50 µs
* erasing one subject among 10^7 in the key store: 0.9 ms median, 121 ms p99
* a database rebuilt from the log after 30 erasures matched the live
  one in all nine tables
* killing one of three log nodes mid-run: commits continue on the quorum
* 600 random crash points and 600 bit flips: no violation, every restart on a
  fresh epoch
* a receipt is about 25 KB and checks in 0.9 ms; a full audit of a million
  records takes 6.2 s on one core, 3.1 s split into segments over two
* a standard Merkle receipt (without salted leaves) leaks a neighbouring
  balance in 0.71 s; with sealwal's leaves a million guesses find nothing

## Limitations

* Python prototype; the log service and replicas share one machine. Next step:
  a native log service on separate hardware.
* The per-request ML-DSA-44 signature adds 2.4 KB per transaction to the log.
* One subject per record: a change that touches several people's data is
  written as one record per person in the same commit.
* Proving only a predicate ("someone at hospital X") instead of the identity
  needs a zero-knowledge proof of the same relation; not implemented.

## Layout

```
sealwal/log.py         writer, signing modes, recovery, group commit
sealwal/format.py      frames, seals, digests
sealwal/merkle.py      RFC 9162 tree, proofs, indexed Tree
sealwal/lms.py         LMS/HSS, epoch key file, replica slices
csrc/lmots.c           LM-OTS chains and LMS tree build
sealwal/provenance.py  binding, records, witnesses, receipts
sealwal/oidc.py        ID tokens and nonces
sealwal/keystore.py    subject keys (SQLite)
sealwal/replica.py     log nodes, witnesses over TCP
sealwal/verify.py      verifier, inclusion and consistency proofs
integrations/postgres  PostgreSQL front end, TPC-C-like and YCSB, replay
bench/                 benchmarks
tests/                 pytest suite
```

## License

MIT, see `LICENSE`.
