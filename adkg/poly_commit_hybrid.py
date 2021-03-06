# from pypairing import ZR, G1
from adkg.poly_commit_bulletproof_blind import PolyCommitBulletproofBlind
from adkg.poly_commit_feldman import PolyCommitFeldman
from pypairing import Curve25519ZR as ZR, Curve25519G as G1
from adkg.proofs import dleq_prove, dleq_verify


class PolyCommitHybrid(PolyCommitFeldman, PolyCommitBulletproofBlind):
    def __init__(self, crs=None, degree_max=33):
        PolyCommitBulletproofBlind.__init__(self, crs, degree_max)

    def commit(self, phi, r):
        bp, feldman, proofs = [], [], []
        for i in range(len(phi.coeffs)):
            bp.append(self.gs[i] ** phi.coeffs[i])
            feldman.append(self.gs[0] ** phi.coeffs[i])
            proofs.append(dleq_prove(self.gs[i], self.gs[0], bp[i], feldman[i], phi.coeffs[i]))
        return [bp, feldman, proofs]

    def verify_commit(self, c):
        bp, feldman, proofs = c
        if len(bp) != len(feldman) or len(bp) != len(proofs):
            return False
        for i in range(len(bp)):
            if not dleq_verify(self.gs[i], self.gs[0], bp[i], feldman[i], proofs[i]):
                return False
        return True

    def create_witness(self, phi, i, r):
        return PolyCommitFeldman.create_witness(self, phi, c, i, r)

    def batch_create_witness(self, c, phi, n, r):
        return PolyCommitFeldman.batch_create_witness(self, phi, c, n, r)

    def double_batch_create_witness(self, cs, phis, n, r):
        return PolyCommitFeldman.double_batch_create_witness(self, cs, phis, n, r)

    def verify_eval(self, c, i, phi_at_i, witness):
        bplist, feldmanlist, _ = c
        return PolyCommitFeldman.verify_eval(self, feldmanlist, i, phi_at_i, witness)


    # Degree specification enables degree enforcement (will return false if polynomial is not of specified degree)
    def batch_verify_eval(self, cs, i, phis_at_i, witness, degree=None):
        feldmancoms = [c[1] for c in cs]
        return PolyCommitFeldman.batch_verify_eval(self, feldmancoms, i, phis_at_i, witness, degree)

    def preprocess_prover(self, level=8):
        PolyCommitBulletproofBlind.preprocess_prover(self, level)

    def preprocess_verifier(self, level=8):
        PolyCommitBulletproofBlind.preprocess_verifier(self, level)
