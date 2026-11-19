"""sealwal: a tamper-evident write-ahead log with (post-quantum) signed group commits."""

from .log import CorruptLogError, GroupCommitter, SealedLog
from .signers import ALG_IDS, make_signer, verify_signature
from .verify import Report, check_proof, prove, verify

__all__ = [
    "SealedLog",
    "GroupCommitter",
    "CorruptLogError",
    "make_signer",
    "verify_signature",
    "verify",
    "prove",
    "check_proof",
    "Report",
    "ALG_IDS",
]
__version__ = "0.1.0"
