from pypairing import ZR, G1

class PolyCommitFeldman:
    def __init__(self, crs):
        self.g = crs

    def commit(self, phi, *args):
        return [self.g ** coeff for coeff in phi.coeffs]

    def verify_eval(self, c, i, phi_at_i, *args):
        exp = ZR(1)
        lhs = G1.identity()
        for j in range(len(c)):
            lhs *= c[j]**exp
            exp *= i
        return lhs == self.g ** phi_at_i

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
