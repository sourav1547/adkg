def test_zr_math():
    from pypairing import Curve25519ZR as ZR

    assert ZR(2) ** 3 == ZR(8)
    assert ZR(200) / 10 == ZR(20)
    assert ZR(14) + 4 == ZR(18)
    assert ZR(10) - ZR(4) == ZR(6)
    a = ZR.rand()
    assert a ** -3 * a ** -5 == a ** -8
    assert (a ** -1) * a == a ** 0
    assert a ** 0 == ZR(1)


def test_group_math():
    from pypairing import Curve25519G as G
    from pypairing import Curve25519ZR as ZR

    g = G.rand()
    g2 = g ** 1
    g3 = g2 ** 1
    a = ZR.rand()
    assert g**a == g2**a
    nega = a * -1
    assert g**a == g**(nega * -1)
    assert g**a == (g**(nega))**-1
    g.preprocess(8)
    g2.preprocess(3)
    assert g**a == g3**a
    assert g**a == g2**a
    h = G.rand()
    h2 = G.rand()
    assert h / h2 == h * h2 ** -1
    assert (h ** -1) ** -1 == h


def test_serialization():
    from pypairing import Curve25519G as G
    from pypairing import Curve25519ZR as ZR

    a = ZR.rand()
    b = G.rand()
    a2 = ZR.rand()
    a2.__setstate__(a.__getstate__())
    b2 = G.rand()
    b2.__setstate__(b.__getstate__())
    assert a == a2
    assert b == b2

def test_serialization2():
    from pypairing import G1
    from pypairing import G2
    from pypairing import GT
    from pypairing import ZR

    a = ZR.rand()
    b = G1.rand()
    c = G2.rand()
    d = GT.rand()
    a2 = ZR.rand()
    a2.__setstate__(a.__getstate__())
    b2 = G1.rand()
    b2.__setstate__(b.__getstate__())
    #c2 = G2.rand()
    #c2.__setstate__(c.__getstate__())
    #d2 = GT.rand()
    #d2.__setstate__(d.__getstate__())
    assert a == a2
    assert b == b2
    #assert c == c2
    #assert d == d2


def test_hashing():
    from pypairing import Curve25519G as G
    from pypairing import Curve25519ZR as ZR
    import pickle

    crs = G.hash_many(b"honeybadger", 10) + ZR.hash_many(b"honeybadger", 2)
    assert crs[0] != crs[1]
    assert type(crs[0]) is G
    assert type(crs[11]) is ZR
    assert len(crs) == 12
    c = ZR.hash(pickle.dumps(crs))
    assert type(c) is ZR
    c2 = ZR.hash(pickle.dumps(crs))
    assert c == c2
    g = G.hash(pickle.dumps(crs))
    g2 = G.hash(pickle.dumps(crs))
    assert g == g2