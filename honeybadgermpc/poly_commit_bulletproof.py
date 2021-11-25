# from honeybadgermpc.betterpairing import ZR, G1
# from pypairing import ZR, G1
from pypairing import Curve25519ZR as ZR, Curve25519G as G1
from honeybadgermpc.proofs import (
    prove_inner_product_one_known,
    verify_inner_product_one_known,
    prove_batch_inner_product_one_known,
    verify_batch_inner_product_one_known,
    prove_double_batch_inner_product_one_known,
    prove_double_batch_inner_product_one_known_but_different,
    prove_double_batch_inner_product_one_known_but_differenter,
    verify_double_batch_inner_product_one_known,
    verify_double_batch_inner_product_one_known_but_differenter,
    MerkleTree,
)
import pickle


class PolyCommitBulletproof:
    def __init__(self, crs=None, degree_max=33):
        if crs is None:
            n = degree_max + 1
            self.gs = G1.hash_many(b"honeybadgerg", n)
            self.u = G1.hash(b"honeybadgeru")
        else:
            assert len(crs) == 2
            [self.gs, self.u] = crs
        #cache [0, i, i**2, i**3, ...] as it will be the same for different polynomials
        self.y_vecs = []

    def commit(self, phi, *args):
        c = G1.identity()
        for i in range(len(phi.coeffs)):
            c *= self.gs[i] ** phi.coeffs[i]
        return c

    def create_witness(self, c, phi, i, *args):
        t = len(phi.coeffs) - 1
        y_vec = [ZR(i) ** j for j in range(t + 1)]
        comm, phi_at_i, iproof = prove_inner_product_one_known(
            phi.coeffs, y_vec, comm=c, crs=[self.gs, self.u]
        )
        #[proof, was_this_generated_in_a_batch]
        return [iproof, False]

    # Create witnesses for points 1 to n. n defaults to 3*degree+1 if unset.
    def batch_create_witness(self, c, phi, n, *args):
        t = len(phi.coeffs) - 1
        if len(self.y_vecs) < n:
            i = len(self.y_vecs)
            while i < n:
                self.y_vecs.append([ZR(i + 1) ** j for j in range(t + 1)])
                i += 1
        comm, phi_at_is, iproofs = prove_batch_inner_product_one_known(
            phi.coeffs, self.y_vecs, comm=c, crs=[self.gs, self.u]
        )
        witnesses = [None] * n
        for j in range(len(witnesses)):
            witnesses[j] = [iproofs[j], True]
        return witnesses

    def double_batch_create_witness(self, cs, phis, n, *args):
        t = len(phis[0].coeffs) - 1
        if len(self.y_vecs) < n:
            i = len(self.y_vecs)
            while i < n:
                self.y_vecs.append([ZR(i + 1) ** j for j in range(t + 1)])
                i += 1
        comms, phis_at_is, iproofs = prove_double_batch_inner_product_one_known_but_differenter(
            [phi.coeffs for phi in phis], self.y_vecs, comms=cs, crs=[self.gs, self.u]
        )
        return iproofs

    def verify_eval(self, c, i, phi_at_i, witness):
        t = witness[0][0] - 1
        y_vec = [ZR(i) ** j for j in range(t + 1)]
        if witness[1]:
            ret = verify_batch_inner_product_one_known(
                c, phi_at_i, y_vec, witness[0], crs=[self.gs, self.u]
            )
        else:
            ret = verify_inner_product_one_known(
                c, phi_at_i, y_vec, witness[0], crs=[self.gs, self.u]
            )
        return ret

    def batch_verify_eval(self, cs, i, phis_at_i, witness, degree):
        y_vec = [ZR(i) ** j for j in range(degree+1)]
        return verify_double_batch_inner_product_one_known_but_differenter(
            cs, phis_at_i, y_vec, witness[0], witness[1], crs=[self.gs, self.u]
        )

    def commit_add(self, a, b):
        return a*b
    
    def commit_sub(self, a, b):
        return a/b

    def preprocess_prover(self, level=8):
        self.u.preprocess(level)
        # 0 to length-1
        for i in range(len(self.gs) - 1):
            self.y_vecs.append([ZR(i + 1) ** j for j in range(len(self.gs))])

    def preprocess_verifier(self, level=8):
        self.u.preprocess(level)
