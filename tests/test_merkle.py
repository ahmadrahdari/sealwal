import hashlib

import pytest

from sealwal import merkle


def ref_root(ls):
    # RFC 9162 MTH, written out recursively
    if len(ls) == 1:
        return ls[0]
    k = 1
    while k * 2 < len(ls):
        k *= 2
    return hashlib.sha256(b"\x01" + ref_root(ls[:k]) + ref_root(ls[k:])).digest()


def leaves(n):
    return [merkle.leaf_hash(i + 1, b"rec%d" % i) for i in range(n)]


@pytest.mark.parametrize("n", list(range(1, 40)) + [63, 64, 65, 127, 128, 129, 1000])
def test_root(n):
    ls = leaves(n)
    assert merkle.root(ls) == ref_root(ls)


@pytest.mark.parametrize("n", list(range(1, 34)) + [100, 257])
def test_audit_paths(n):
    ls = leaves(n)
    r = merkle.root(ls)
    for i in range(n):
        path = merkle.audit_path(i, ls)
        assert len(path) <= max(1, (n - 1).bit_length())
        assert merkle.root_from_path(i, n, ls[i], path) == r


def test_bad_paths():
    ls = leaves(13)
    r = merkle.root(ls)
    path = merkle.audit_path(5, ls)
    assert merkle.root_from_path(5, 13, ls[6], path) != r
    assert merkle.root_from_path(6, 13, ls[5], path) != r
    # wrong shape for the size is rejected (13 vs 14 has the same shape for
    # leaf 5, but the seal pins the size so that can't be abused)
    assert merkle.root_from_path(5, 7, ls[5], path) is None
    assert merkle.root_from_path(13, 13, ls[5], path) is None


def test_leaf_vs_node_prefix():
    a, b = leaves(2)
    assert merkle.node_hash(a, b) != hashlib.sha256(b"\x00" + a + b).digest()


def test_empty():
    with pytest.raises(ValueError):
        merkle.root([])


def test_frontier():
    ls = leaves(300)
    f = merkle.Frontier()
    for i, leaf in enumerate(ls):
        f.append(leaf)
        assert f.root() == merkle.root(ls[:i + 1])


def test_consistency_all_pairs():
    ls = leaves(70)
    for n in range(1, 71):
        for m in range(1, n + 1):
            p = merkle.consistency_proof(m, ls[:n])
            assert merkle.verify_consistency(m, n, merkle.root(ls[:m]), merkle.root(ls[:n]), p)


def test_consistency_catches_rewrite():
    ls = leaves(40)
    forged = ls[:10] + [merkle.leaf_hash(11, b"evil")] + ls[11:]
    # old head of size 12 already contained record 11, so the forged log
    # can't prove it extends it
    p = merkle.consistency_proof(12, forged)
    assert not merkle.verify_consistency(12, 40, merkle.root(ls[:12]), merkle.root(forged), p)
    # a prefix that ends before the change still checks out
    p = merkle.consistency_proof(8, forged)
    assert merkle.verify_consistency(8, 40, merkle.root(ls[:8]), merkle.root(forged), p)
    # garbage in the proof
    p = merkle.consistency_proof(12, ls)
    p[1] = bytes(32)
    assert not merkle.verify_consistency(12, 40, merkle.root(ls[:12]), merkle.root(ls), p)
