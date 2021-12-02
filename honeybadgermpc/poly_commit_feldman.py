# from pypairing import ZR, G1
from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp

class PolyCommitFeldman:
    def __init__(self, crs):
        self.g = crs

    def commit(self, phi, *args):
        return [self.g ** coeff for coeff in phi.coeffs]

    def verify_eval(self, c, i, phi_at_i, *args):
        n = len(c)
        exps = []
        texp = ZR(1)
        for _ in range(n):
            exps.append(texp)
            texp *=i
        lhs = multiexp(c, exps)
        valid = lhs == self.g.pow(phi_at_i)
        return valid

    def create_witness(*args):
        return None

    def batch_create_witness(self, phi, r, n):
        return [None] * n
    
    def double_batch_create_witness(self, phis, r, n):
        return [[None] * len(phis)] * n
    
    def batch_verify_eval(self, cs, i, phis_at_i, witness=None):
        for j in range(len(cs)):
            if not self.verify_eval(cs[j], i, phis_at_i[j]):
                return False
        return True
    
    def preprocess(self, level=8):
        self.g.preprocess(level)
