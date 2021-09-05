import random
import math
from pypairing import ZR, G1, G2, pair
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_amt_unity import PolyCommitAMTUnity, get_all_roots_of_unity, bit_reverse, gen_crs


class SimulatedPclProof:
    def __init__(self, size):
        self.fake_content = [random.getrandbits(8) for _ in range(size)]
    def __mul__(self, other):
        # No op
        return self
    def __pow__(self, power, modulo=None):
        # No op
        return self
    def __imul__(self, other):
        # No op
        return self

class SimulatedPclCom:
    def __init__(self):
        size = 32
        self.fake_content = [random.getrandbits(8) for _ in range(size)]
    def __mul__(self, other):
        # No op
        return self
    def __pow__(self, power, modulo=None):
        # No op
        return self
    def __imul__(self, other):
        # No op
        return self

class PolyCommitLoglinDummy:

    def __init__(self, crs=None, degree_max=33):
        self.simulated_type = "Loglin"

    # Takes a random length of bytes
    def get_random_bytes(self, length):
        return [random.getrandbits(8) for _ in range(length)]

    # One polycommitment for Polycommitloglin is one field element is 32 bytes
    def polycommit_loglin_bytes_generate(self, phi):
        polycommit_loglin_comm_length = 32
        return self.get_random_bytes(polycommit_loglin_comm_length)

    def commit(self, phi, r):
        #return self.polycommit_loglin_bytes_generate(phi)
        #return G1(1)
        return SimulatedPclCom()

    def create_witness(self, phi, r, i):
        pass

    # Create witnesses for points 1 to n. n defaults to 3*degree+1 if unset.
    def batch_create_witness(self, phi, r, n=None):
        pass

    def num_calc(self, n):
        if n == 1:
            return 1
        if n == 0:
            return 0
        if n%2 == 1:
            return self.num_calc(int(n/2)) + 3
        else:
            return self.num_calc(int(n/2)) + 2

    # Polycommitloglin's share is 32 bytes
    # Polycommitloglin's proof is log2(t)*2*32 + log2(n)*log2(t)*32
    # We are comparing under n = 3 * t + 1
    def double_batch_create_witness_polycommit_loglin_bytes_generator(self, phis):
        t = len(phis[0].coeffs) - 1
        n = 3 * t + 1
        numofverifiers = n
        #polycommit_loglin_msg_length = 32 + (math.ceil(math.log2(t)) + 1) * 2 * 32
        polycommit_loglin_msg_length = 32 + self.num_calc(n) * 32
        #random_msg = [self.get_random_bytes(polycommit_loglin_msg_length) * len(phis)]
        random_witnesses = [SimulatedPclProof(polycommit_loglin_msg_length) for _ in range(len(phis))]
        return [random_witnesses.copy() for _ in range(numofverifiers)]

    def double_batch_create_witness(self, phis, r, n=None):
        return self.double_batch_create_witness_polycommit_loglin_bytes_generator(phis)

    # Always eval to true
    def verify_eval(self, c, i, phi_at_i, witness):
        return True

    # Always eval to true
    def batch_verify_eval(self, cs, i, phis_at_i, witness, degree=None):
        return True

    def preprocess_prover(self, level=8):
        pass

    def preprocess_verifier(self, level=8):
        pass

class SimulatedAMTProof:
    def __init__(self, fake_proof):
        self.fake_content = fake_proof

class SimulatedAMTCom:
    def __init__(self, fake_com):
        self.fake_content = fake_com
    
class PolyCommitAMTDummy:
    def __init__(self, n, crs=None, degree_max=64):
        self.simulated_type = "AMT"
        if crs is None:
            crs = gen_crs(degree_max=64)
        self.pc = PolyCommitAMTUnity(crs, n)

    # Takes a random length of bytes
    def get_random_bytes(self, length):
        return [random.getrandbits(8) for _ in range(length)]

    # One polynomial commitment for AMT is one field element is 32 bytes
    def polycommit_amt_bytes_generate(self, phi):
        amt_comm_length = 32
        return self.get_random_bytes(amt_comm_length)

    def commit(self, phi, r):
        # return self.polycommit_amt_bytes_generate(phi)
        fake_com = self.pc.commit(phi)
        return SimulatedAMTCom(fake_com)

    def create_witness(self, phi, r, i):
        pass

    # Create witnesses for points 1 to n. n defaults to 3*degree+1 if unset.
    def batch_create_witness(self, phi, r, n=None):
        pass

    # # AMT's share is 32 bytes
    # # AMT's proof is ceil(log2(n)+1) * 32
    # # We are comparing under n = 3 * t + 1
    # # Reference: libpolycrypto/app/BandwidthCalc.cpp
    # def double_batch_create_witness_amt_bytes_generator(self, phis):
    #     t = len(phis[0].coeffs) - 1
    #     n = 3 * t + 1
    #     numofverifiers = n
    #     amt_msg_length = 32 + (math.ceil(math.log2(n)) + 1) * 32
    #     # random_msg = [self.get_random_bytes(amt_msg_length) * len(phis)]
    #     # return [random_msg for _ in range(numofverifiers)]
    #     random_witnesses = [SimulatedAMTProof() for _ in range(len(phis))]
    #     return [random_witnesses for _ in range(numofverifiers)]

    def double_batch_create_witness(self, phis, r, n=None):
        # return self.double_batch_create_witness_amt_bytes_generator(phis)
        t = len(phis[0].coeffs) - 1
        n = 3 * t + 1
        numofverifiers = n
        # random_witnesses = [SimulatedAMTProof(phis[i], self.pc) for i in range(len(phis))]
        # return [random_witnesses for _ in range(numofverifiers)]
        return [[SimulatedAMTProof(self.pc.create_witness(phis[i], j)) for i in range(len(phis))] for j in range(numofverifiers)]
        
    # Always eval to true
    def verify_eval(self, c, i, phi_at_i, witness):
        return True

    # Always eval to true
    def batch_verify_eval(self, cs, i, phis_at_i, witness, degree=None):
        return True

    def preprocess_prover(self, level=8):
        pass

    def preprocess_verifier(self, level=8):
        pass