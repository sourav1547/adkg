# from honeybadgermpc.betterpairing import ZR, G1
#from pypairing import ZR, G1
from honeybadgermpc.poly_commit_bulletproof_blind import PolyCommitBulletproofBlind
from honeybadgermpc.poly_commit_feldman import PolyCommitFeldman
from pypairing import Curve25519ZR as ZR, Curve25519G as G1
from honeybadgermpc.proofs import dleq_batch_prove, dleq_batch_verify


class PolyCommitHybrid(PolyCommitFeldman, PolyCommitBulletproofBlind):
    def __init__(self, crs=None, degree_max=33):
        PolyCommitBulletproofBlind.__init__(self, crs, degree_max)

    def commit(self, phi, r):
        bp, feldman, bp_c = [], [], G1.identity()
        for i in range(len(phi.coeffs)):
            # temp_prod = self.gs[i] ** phi.coeffs[i]
            temp_prod = self.gs[i].pow(phi.coeffs[i])
            bp_c *= temp_prod
            bp.append(temp_prod)
            feldman.append(self.gs[0].pow(phi.coeffs[i]))
        batched_proof = dleq_batch_prove(self.gs, self.gs[0], bp, feldman, phi.coeffs)
        return [bp, feldman, batched_proof], bp_c

    def verify_commit(self, c):
        bp, feldman, proofs = c
        if len(bp) != len(feldman) or len(bp) != len(proofs[1]):
            return False
        return dleq_batch_verify(self.gs, self.gs[0],bp, feldman, proofs)

    def create_witness(self, phi, i, r):
        return PolyCommitFeldman.create_witness(self, phi, i, r)

    def batch_create_witness(self, c, phi, n, r):
        return PolyCommitFeldman.batch_create_witness(self, phi, c, n, r)

    def double_batch_create_witness(self, cs, phis, n, r):
        return PolyCommitFeldman.double_batch_create_witness(self, cs, phis, n, r)

    def verify_eval(self, c, i, phi_at_i, witness):
        _, feldmanlist, _ = c
        return PolyCommitFeldman.verify_eval(self, feldmanlist, i, phi_at_i, witness)


    # Degree specification enables degree enforcement (will return false if polynomial is not of specified degree)
    def batch_verify_eval(self, cs, i, phis_at_i, witness, degree=None):
        feldmancoms = [c[1] for c in cs]
        return PolyCommitFeldman.batch_verify_eval(self, feldmancoms, i, phis_at_i, witness, degree)

    def preprocess_prover(self, level=8):
        PolyCommitBulletproofBlind.preprocess_prover(self, level)

    def preprocess_verifier(self, level=8):
        PolyCommitBulletproofBlind.preprocess_verifier(self, level)
