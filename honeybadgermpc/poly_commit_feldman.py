from pypairing import ZR, G1
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1

class PolyCommitFeldman:
    def __init__(self, crs):
        self.g = crs

    def commit(self, phi, *args):
        # return [self.g ** coeff for coeff in phi.coeffs]
        return [self.g.pow(coeff) for coeff in phi.coeffs]

    def verify_eval(self, c, i, phi_at_i, *args):
        exp = ZR(1)
        lhs = G1.identity()
        for j in range(len(c)):
            # lhs *= c[j]**exp
            lhs *= c[j].pow(exp)
            exp *= i
        # return lhs == self.g ** phi_at_i
        return lhs == self.g.pow(phi_at_i)

    def create_witness(*args):
        return None

    def batch_create_witness(self, c, phi, n, *args):
        return [None] * n
    
    def double_batch_create_witness(self, cs, phis, n, *args):
        return [[None] * len(phis)] * n
    
    def batch_verify_eval(self, cs, i, phis_at_i, *args):
        for j in range(len(cs)):
            if not self.verify_eval(cs[j], i, phis_at_i[j]):
                return False
        return True
    
    def preprocess(self, level=8):
        self.g.preprocess(level)

    #homomorphically add commitments
    def commit_add(self, a, b):
        if len(a) > len(b):
            longer = a
            shorter = b
        else:
            longer = b
            shorter = a
        #the **1 is necessary to create a new copy and avoid dumb memory bugs
        out = [entry ** 1 for entry in longer]
        for i in range(len(shorter)):
            out[i] *=  shorter[i]
        return out
    
    def commit_sub(self, a, b):
        if len(a) > len(b):
            longer = a
            shorter = [entry**(-1) for entry in b]
        else:
            longer = [entry**(-1) for entry in b]
            shorter = a
        out = [entry ** 1 for entry in longer]
        for i in range(len(shorter)):
            out[i] *=  shorter[i]
        return out

    def get_secret_commit(self, c):
        return c[0]