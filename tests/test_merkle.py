import hashlib

import pytest

from sealwal import merkle


def reference_root(leaves):
    """Straight transcription of RFC 9162's recursive MTH definition."""
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + reference_root(leaves[:k]) + reference_root(leaves[k:])).digest()


def leaves(n):
    return [merkle.leaf_hash(i + 1, f"rec{i}".encode()) for i in range(n)]


@pytest.mark.parametrize("n", list(range(1, 40)) + [63, 64, 65, 127, 128, 129, 1000])
def test_root_matches_reference(n):
    ls = leaves(n)
    assert merkle.root(ls) == reference_root(ls)


@pytest.mark.parametrize("n", list(range(1, 34)) + [100, 257])
def test_every_audit_path_verifies(n):
    ls = leaves(n)
    r = merkle.root(ls)
    for i in range(n):
        path = merkle.audit_path(i, ls)
        assert len(path) <= max(1, (n - 1).bit_length())
        assert merkle.root_from_path(i, n, ls[i], path) == r


def test_wrong_leaf_or_index_fails():
    ls = leaves(13)
    r = merkle.root(ls)
    path = merkle.audit_path(5, ls)
    assert merkle.root_from_path(5, 13, ls[6], path) != r
    assert merkle.root_from_path(6, 13, ls[5], path) != r
    # A path of the wrong shape for the claimed size is rejected. (Sizes with
    # the same shape, e.g. 13 vs 14 for leaf 5, are told apart by the seal,
    # which fixes the batch size: see check_proof.)
    assert merkle.root_from_path(5, 7, ls[5], path) is None
    assert merkle.root_from_path(13, 13, ls[5], path) is None


def test_leaf_and_node_domains_differ():
    # A leaf whose payload looks like two child hashes must not equal the node.
    a, b = leaves(2)
    assert merkle.node_hash(a, b) != hashlib.sha256(b"\x00" + a + b).digest()


def test_empty_batch_rejected():
    with pytest.raises(ValueError):
        merkle.root([])
