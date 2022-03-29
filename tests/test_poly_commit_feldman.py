from pypairing import ZR, G1
from adkg.polynomial import polynomials_over
from adkg.poly_commit_feldman import PolyCommitFeldman

def test_pc_const():
    t = 6
    crs = G1.rand()
    pc = PolyCommitFeldman(crs)
    phi = polynomials_over(ZR).random(t)
    c = pc.commit(phi)
    assert pc.verify_eval(c, 3, phi(3))
    assert pc.verify_eval(c, 20, phi(20))
    assert pc.verify_eval(c, 0, phi(0))
    assert not pc.verify_eval(c, 3, phi(4))
    assert not pc.verify_eval(c, 3, ZR.rand())