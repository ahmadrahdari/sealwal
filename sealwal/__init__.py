"""sealwal: tamper-evident write-ahead log with post-quantum signed group commits."""

from .log import CorruptLogError, GroupCommitter, SealedLog
from .signers import ALG_IDS, make_signer, verify_signature
from .privacy import Erased, KeyStore
from .verify import (Report, check_consistency, check_proof, prove, prove_consistency,
                     read_records, verify)

__version__ = "0.4.0"
