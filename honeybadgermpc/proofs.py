#from honeybadgermpc.betterpairing import ZR, G1, hashg1list, hashzrlist, hash_list_to_bytes, inner_product
from pypairing import ZR, G1, hashg1s as hashg1list, hashfrs as hashzrlist, dotprod as inner_product, hashg1sbn as hashg1listbn
from honeybadgermpc.betterpairing import hash_list_to_bytes
import pickle
import math
import hashlib


class MerkleTree:
    def __init__(self, leaves=None):
        if leaves is None:
            self.leaves = []
        else:
            assert type(leaves) in [list, tuple]
            self.leaves = leaves
        self.tree = None

    def build_tree(self):
        bottomrow = 2 ** math.ceil(math.log(len(self.leaves), 2))
        self.tree = [b""] * (2 * bottomrow)
        for i in range(len(self.leaves)):
            self.tree[bottomrow + i] = MerkleTree.hash(self.leaves[i])
        for i in range(bottomrow - 1, 0, -1):
            self.tree[i] = MerkleTree.hash(self.tree[i * 2] + self.tree[i * 2 + 1])

    def append(self, leaf):
        assert type(leaf) is bytes
        self.leaves.append(leaf)
        self.tree = None

    def append_many(self, leaves):
        assert type(leaves) in [list, tuple]
        for leaf in leaves:
            assert type(leaf) is bytes
        self.leaves += list(leaves)
        self.tree = None

    def get_root_hash(self):
        if self.tree is None:
            self.build_tree()
        return self.tree[1]

    def get_branch(self, index):
        if self.tree is None:
            self.build_tree()
        res = []
        t = index + (len(self.tree) >> 1)
        while t > 1:
            res.append(self.tree[t ^ 1])  # we are picking up the sibling
            t //= 2
        return [res, index]

    @staticmethod
    def hash(item):
        assert type(item) is bytes
        return hashlib.sha256(item).digest()

    @staticmethod
    def verify_membership(leaf, branch, root_hash):
        mbranch, index = branch
        assert type(leaf) is bytes
        # Index has information on whether we are facing a left or a right sibling
        tmp = MerkleTree.hash(leaf)
        tindex = index
        for br in mbranch:
            if tindex % 2 == 1:
                tmp = MerkleTree.hash(br + tmp)
            else:
                tmp = MerkleTree.hash(tmp + br)
            tindex >>= 1
        return tmp == root_hash


# Inner product (aka dot product) argument from Bulletproofs paper. Not zero knowledge!
# g and h are vectors of G1 elements, a and b are vectors that form the inner product
def prove_inner_product(a_vec, b_vec, comm=None, crs=None):
    def recursive_proof(g_vec, h_vec, u, a_vec, b_vec, n, P, transcript):
        if n == 1:
            proof = []
            proof.append([a_vec[0], b_vec[0]])
            return proof
        proofstep = []
        if n % 2 == 1:
            na, nb = a_vec[-1] * -1, b_vec[-1] * -1
            P *= g_vec[-1] ** (na) * h_vec[-1] ** (nb) * u ** (-na * nb)
            proofstep.append(na)
            proofstep.append(nb)
        n_p = n // 2
        cl = ZR(0)
        cr = ZR(0)
        L = G1.identity()
        R = G1.identity()
        for i in range(n_p):
            cl += a_vec[:n_p][i] * b_vec[n_p:][i]
            cr += a_vec[n_p:][i] * b_vec[:n_p][i]
            L *= g_vec[n_p:][i] ** a_vec[:n_p][i] * h_vec[:n_p][i] ** b_vec[n_p:][i]
            R *= g_vec[:n_p][i] ** a_vec[n_p:][i] * h_vec[n_p:][i] ** b_vec[:n_p][i]
        L *= u ** cl
        R *= u ** cr
        # Fiat Shamir L, R, state...
        #transcript += pickle.dumps([g_vec, h_vec, u, P, L, R])
        transcript += pickle.dumps(hashg1list(g_vec + h_vec + [u, P, L, R]))
        x = ZR.hash(transcript)
        xi = x ** -1
        # this part must come after the challenge is generated, which must
        # come after L and R are calculated. Don't try to condense the loops
        g_vec_p, h_vec_p, a_vec_p, b_vec_p = [], [], [], []
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i] ** xi * g_vec[n_p:][i] ** x)
            h_vec_p.append(h_vec[:n_p][i] ** x * h_vec[n_p:][i] ** xi)
            a_vec_p.append(a_vec[:n_p][i] * x + a_vec[n_p:][i] * xi)
            b_vec_p.append(b_vec[:n_p][i] * xi + b_vec[n_p:][i] * x)
        P_p = L ** (x * x) * P * R ** (xi * xi)
        proof = recursive_proof(
            g_vec_p, h_vec_p, u, a_vec_p, b_vec_p, n_p, P_p, transcript
        )
        proofstep.append(L)
        proofstep.append(R)
        proof.append(proofstep)
        return proof

    n = len(a_vec)
    assert len(b_vec) == n
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        h_vec = G1.hash_many(b"honeybadgerh", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, h_vec, u] = crs
        g_vec = g_vec[:n]
        h_vec = h_vec[:n]
    if comm is not None:
        P = comm * G1.identity()
    else:
        comm = G1.identity()
        for i in range(n):
            comm *= g_vec[i] ** a_vec[i] * h_vec[i] ** b_vec[i]
    iprod = ZR(0)
    for i in range(n):
        iprod += a_vec[i] * b_vec[i]
    P = comm * u ** iprod
    transcript = b""
    return [
        comm,
        iprod,
        [n] + recursive_proof(g_vec, h_vec, u, a_vec, b_vec, n, P, transcript),
    ]


def verify_inner_product(comm, iprod, proof, crs=None):
    def recursive_verify(g_vec, h_vec, u, proof, n, P, transcript):
        if n == 1:
            a, b = proof[0][0], proof[0][1]
            return P == g_vec[0] ** a * h_vec[0] ** b * u ** (a * b)
        if n % 2 == 1:
            [na, nb, L, R] = proof[-1]
            P *= g_vec[-1] ** (na) * h_vec[-1] ** (nb) * u ** (-na * nb)
        else:
            [L, R] = proof[-1]
        #transcript += pickle.dumps([g_vec, h_vec, u, P, L, R])
        transcript += pickle.dumps(hashg1list(g_vec + h_vec + [u, P, L, R]))
        x = ZR.hash(transcript)
        xi = x ** -1
        n_p = n // 2
        g_vec_p = []
        h_vec_p = []
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i] ** xi * g_vec[n_p:][i] ** x)
            h_vec_p.append(h_vec[:n_p][i] ** x * h_vec[n_p:][i] ** xi)
        P_p = L ** (x * x) * P * R ** (xi * xi)
        return recursive_verify(g_vec_p, h_vec_p, u, proof[:-1], n_p, P_p, transcript)

    n = proof[0]
    iproof = proof[1:]
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        h_vec = G1.hash_many(b"honeybadgerh", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, h_vec, u] = crs
    P = comm * u ** iprod
    transcript = b""
    return recursive_verify(g_vec, h_vec, u, iproof, n, P, transcript)


# Inner product argument where one vector (b_vec) is known by both parties
def prove_inner_product_one_known(a_vec, b_vec, comm=None, crs=None):
    def recursive_proof(g_vec, a_vec, b_vec, u, n, P, transcript):
        if n == 1:
            proof = []
            proof.append([a_vec[0]])
            return proof
        proofstep = []
        if n % 2 == 1:
            na = a_vec[-1] * -1
            P *= g_vec[-1] ** (na) * u ** (na * b_vec[-1])
            proofstep.append(na)
        n_p = n // 2
        cl = ZR(0)
        cr = ZR(0)
        L = G1.identity()
        R = G1.identity()
        for i in range(n_p):
            cl += a_vec[:n_p][i] * b_vec[n_p:][i]
            cr += a_vec[n_p:][i] * b_vec[:n_p][i]
            L *= g_vec[n_p:][i] ** a_vec[:n_p][i]
            R *= g_vec[:n_p][i] ** a_vec[n_p:][i]
        L *= u ** cl
        R *= u ** cr
        # Fiat Shamir L, R, state...
        #transcript += pickle.dumps([g_vec, u, P, L, R])
        transcript += pickle.dumps(hashg1list(g_vec + [u, P, L, R]))
        x = ZR.hash(transcript)
        xi = x ** -1
        # this part must come after the challenge is generated, which must
        # come after L and R are calculated. Don't try to condense the loops
        g_vec_p, a_vec_p, b_vec_p = [], [], []
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i] ** xi * g_vec[n_p:][i] ** x)
            a_vec_p.append(a_vec[:n_p][i] * x + a_vec[n_p:][i] * xi)
            b_vec_p.append(b_vec[:n_p][i] * xi + b_vec[n_p:][i] * x)
        P_p = L ** (x * x) * P * R ** (xi * xi)
        proof = recursive_proof(g_vec_p, a_vec_p, b_vec_p, u, n_p, P_p, transcript)
        proofstep.append(L)
        proofstep.append(R)
        proof.append(proofstep)
        return proof

    n = len(a_vec)
    assert len(b_vec) == n
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, u] = crs
        g_vec = g_vec[:n]
    if comm is not None:
        P = comm * G1.identity()
    else:
        comm = G1.identity()
        for i in range(n):
            comm *= g_vec[i] ** a_vec[i]
    iprod = ZR(0)
    for i in range(n):
        iprod += a_vec[i] * b_vec[i]
    P = comm * u ** iprod
    transcript = b""
    return [
        comm,
        iprod,
        [n] + recursive_proof(g_vec, a_vec, b_vec, u, n, P, transcript),
    ]


def verify_inner_product_one_known(comm, iprod, b_vec, proof, crs=None):
    def recursive_verify(g_vec, b_vec, u, proof, n, P, transcript):
        if n == 1:
            a, b = proof[0][0], b_vec[0]
            return P == g_vec[0] ** a * u ** (a * b)
        if n % 2 == 1:
            [na, L, R] = proof[-1]
            P *= g_vec[-1] ** (na) * u ** (na * b_vec[-1])
        else:
            [L, R] = proof[-1]
        #transcript += pickle.dumps([g_vec, u, P, L, R])
        transcript += pickle.dumps(hashg1list(g_vec + [u, P, L, R]))
        x = ZR.hash(transcript)
        xi = x ** -1
        n_p = n // 2
        g_vec_p = []
        b_vec_p = []
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i] ** xi * g_vec[n_p:][i] ** x)
            b_vec_p.append(b_vec[:n_p][i] * xi + b_vec[n_p:][i] * x)
        P_p = L ** (x * x) * P * R ** (xi * xi)
        return recursive_verify(g_vec_p, b_vec_p, u, proof[:-1], n_p, P_p, transcript)

    n = proof[0]
    iproof = proof[1:]
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, u] = crs
        g_vec = g_vec[:n]
    P = comm * u ** iprod
    transcript = b""
    return recursive_verify(g_vec, b_vec, u, iproof, n, P, transcript)


# Inner product argument where one vector (b_vec) is known by both parties
# Precomputing u is recommended
def prove_batch_inner_product_one_known(a_vec, b_vecs, comm=None, crs=None):
    def recursive_proofs(g_vec, a_vec, b_vecs, u, n, P_vec, transcript):
        if n == 1:
            proofs = [None] * len(b_vecs)
            for j in range(len(proofs)):
                proofs[j] = [[a_vec[0]]]
            return proofs
        proofsteps = [[] for _ in range(len(b_vecs))]
        if n % 2 == 1:
            na = a_vec[-1] * -1
            for j in range(len(P_vec)):
                P_vec[j] *= g_vec[-1] ** (na) * u ** (na * b_vecs[j][-1])
                proofsteps[j].append(na)
        n_p = n // 2
        cl_vec = [ZR(0) for _ in range(len(b_vecs))]
        cr_vec = [ZR(0) for _ in range(len(b_vecs))]
        La = G1.identity()
        Ra = G1.identity()
        L_vec = [None] * len(b_vecs)
        R_vec = [None] * len(b_vecs)
        for i in range(n_p):
            La *= g_vec[n_p:][i] ** a_vec[:n_p][i]
            Ra *= g_vec[:n_p][i] ** a_vec[n_p:][i]
        for j in range(len(b_vecs)):
            #for i in range(n_p):
            #    cl_vec[j] += a_vec[:n_p][i] * b_vecs[j][n_p:][i]
            #    cr_vec[j] += a_vec[n_p:][i] * b_vecs[j][:n_p][i]
            cl_vec[j] = inner_product(a_vec[:n_p], b_vecs[j][n_p:2*n_p])
            cr_vec[j] = inner_product(a_vec[n_p:2*n_p], b_vecs[j][:n_p])
            L_vec[j] = La * (u ** cl_vec[j])
            R_vec[j] = Ra * (u ** cr_vec[j])
        # Fiat Shamir
        # Make a merkle tree over everything that varies between verifiers
        # TODO: na should be in the transcript
        tree = MerkleTree()
        #for j in range(len(b_vecs)):
        #    tree.append(pickle.dumps([b_vecs[j], P_vec[j], L_vec[j], R_vec[j]]))
        b_hashes = [hashzrlist(b_vecs[i]) for i in range(len(b_vecs))]
        leaves = [hash_list_to_bytes(
            [b_hashes[j], hashg1list([P_vec[j], L_vec[j], R_vec[j]])]
            ) for j in range(len(b_vecs))]
        tree.append_many(leaves)
        roothash = tree.get_root_hash()
        for j in range(len(b_vecs)):
            branch = tree.get_branch(j)
            proofsteps[j].append(roothash)
            proofsteps[j].append(branch)
        transcript += pickle.dumps([hashg1list(g_vec), roothash])
        x = ZR.hash(transcript)
        xi = x ** -1
        # this part must come after the challenge is generated, which must
        # come after L and R are calculated. Don't try to condense the loops
        g_vec_p, a_vec_p = [], []
        b_vecs_p = [[] for _ in range(len(b_vecs))]
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i] ** xi * g_vec[n_p:][i] ** x)
            a_vec_p.append(a_vec[:n_p][i] * x + a_vec[n_p:][i] * xi)
            for j in range(len(b_vecs)):
                b_vecs_p[j].append(b_vecs[j][:n_p][i] * xi + b_vecs[j][n_p:][i] * x)
        x2, xi2 = x * x, xi * xi
        Lax2Raxi2 = La ** x2 * Ra ** xi2
        for j in range(len(P_vec)):
            # Instead of doing L_vec[j]**(x2)*P_vec[j]*R_vec[j]**(xi2), save computation
            P_vec[j] *= Lax2Raxi2 * u ** (x2 * cl_vec[j] + xi2 * cr_vec[j])
        proofs = recursive_proofs(g_vec_p, a_vec_p, b_vecs_p, u, n_p, P_vec, transcript)
        for j in range(len(proofs)):
            proofsteps[j].append(L_vec[j])
            proofsteps[j].append(R_vec[j])
            proofs[j].append(proofsteps[j])
        return proofs

    n = len(a_vec)
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, u] = crs
        g_vec = g_vec[:n]
    if comm is None:
        comm = G1.identity()
        for i in range(n):
            comm *= g_vec[i] ** a_vec[i]
    iprods = [ZR(0) for _ in range(len(b_vecs))]
    P_vec = [None] * len(b_vecs)
    for j in range(len(b_vecs)):
        for i in range(n):
            iprods[j] += a_vec[i] * b_vecs[j][i]
        P_vec[j] = comm * u ** iprods[j]
    transcript = pickle.dumps(u)
    proofs = recursive_proofs(g_vec, a_vec, b_vecs, u, n, P_vec, transcript)
    for j in range(len(proofs)):
        proofs[j].insert(0, n)
    return [comm, iprods, proofs]


# Verify an inner product argument (with one vector known) that was generated in a batch
# Not to be confused with a function that does multiple verifications at once
def verify_batch_inner_product_one_known(comm, iprod, b_vec, proof, crs=None):
    def recursive_verify(g_vec, b_vec, u, proof, n, P, transcript):
        if n == 1:
            a, b = proof[0][0], b_vec[0]
            return P == g_vec[0] ** a * u.pow(a * b)
        if n % 2 == 1:
            [na, roothash, branch, L, R] = proof[-1]
            P *= g_vec[-1] ** (na) * u.pow(na * b_vec[-1])
        else:
            [roothash, branch, L, R] = proof[-1]
        leaf = hash_list_to_bytes(
                [hashzrlist(b_vec), hashg1list([P, L, R])]
            )
        if not MerkleTree.verify_membership(
            leaf, branch, roothash
        ):
            return False
        transcript += pickle.dumps([hashg1list(g_vec), roothash])
        x = ZR.hash(transcript)
        xi = x ** -1
        n_p = n // 2
        g_vec_p = []
        b_vec_p = []
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i].pow(xi) * g_vec[n_p:][i].pow(x))
            b_vec_p.append(b_vec[:n_p][i] * xi + b_vec[n_p:][i] * x)
        P_p = L ** (x * x) * P * R ** (xi * xi)
        return recursive_verify(g_vec_p, b_vec_p, u, proof[:-1], n_p, P_p, transcript)

    n = proof[0]
    iproof = proof[1:]
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, u] = crs
        g_vec = g_vec[:n]
    P = comm * u.pow(iprod)
    transcript = pickle.dumps(u)
    return recursive_verify(g_vec, b_vec, u, iproof, n, P, transcript)


# Inner product argument where one vector (b_vec) is known by both parties
# Precomputing u is recommended
# The proofs_p is a list of lists where
# proofs_p[i][j] returns the proof of dot product of a_vecs[i] on b_vecs[j].
# b_vecs is expanded first so that len(New b_vecs) = len(a_vecs) * len(b_vecs)
# for the bullet proof helper function.

#@profile
def prove_double_batch_inner_product_one_known(a_vecs, b_vecs, comms=None, crs=None):
    #@profile
    def recursive_proofs(g_vec, a_vecs, b_vecs, u, n, P_vec, transcript):
        #row_length = len(b_vecs)//len(a_vecs)
        numproofs = len(P_vec)
        row_length = numproofs//len(a_vecs)
        col_length = numproofs//len(b_vecs)
        numverifiers = row_length
        _ = [g.preprocess(5) for g in g_vec]
        if n == 1:
            proofs = [None] * numproofs
            for i in range(len(proofs) // row_length):
                for j in range(row_length):
                    abs_idx = i * row_length + j
                    proofs[abs_idx] = [[a_vecs[i][0]]]
            return proofs
        proofsteps = [[] for _ in range(numproofs)]
        if n % 2 == 1:
            for i in range(numproofs // row_length):
                na = a_vecs[i][-1] * -1
                gtail = g_vec[-1].pow(na)
                for j in range(row_length):
                    abs_idx = i * row_length + j
                    P_vec[abs_idx] *= gtail * u.pow(na * b_vecs[j][-1])
                    proofsteps[abs_idx].append(na)
        n_p = n // 2
        cl_vec = [0 for _ in range(len(P_vecs))]
        cr_vec = [0 for _ in range(len(P_vecs))]
        L_vec = [None] * len(P_vecs)
        R_vec = [None] * len(P_vecs)
        Las = [G1.identity() for _ in range(len(a_vecs))]
        Ras = [G1.identity() for _ in range(len(a_vecs))]
        for j in range(len(a_vecs)):
            for i in range(n_p):
                Las[j] *= g_vec[n_p:][i].pow(a_vecs[j][:n_p][i])
                Ras[j] *= g_vec[:n_p][i].pow(a_vecs[j][n_p:][i])
        for i in range(numproofs // row_length):
            for j in range(row_length):
                abs_idx = i * row_length + j
                cl_vec[abs_idx] = inner_product(a_vecs[i][:n_p], b_vecs[j][n_p:2*n_p])
                cr_vec[abs_idx] = inner_product(a_vecs[i][n_p:2*n_p], b_vecs[j][:n_p])
                L_vec[abs_idx] = Las[i] * (u.pow(cl_vec[abs_idx]))
                R_vec[abs_idx] = Ras[i] * (u.pow(cr_vec[abs_idx]))
        # Fiat Shamir
        # Make a merkle tree over everything that varies between verifiers
        # TODO: na should be in the transcript
        tree = MerkleTree()
        b_hashes = [hashzrlist(b_vecs[i]) for i in range(len(b_vecs))]
        leaves = [hash_list_to_bytes(
            [b_hashes[j%len(b_vecs)], hashg1list([P_vec[j], L_vec[j], R_vec[j]])]
            ) for j in range(numproofs)]
        tree.append_many(leaves)
        roothash = tree.get_root_hash()
        #for h in range(numverifiers):
        for j in range(len(P_vecs)):
            branch = tree.get_branch(j)
            proofsteps[j].append(roothash)
            proofsteps[j].append(branch)
        transcript += pickle.dumps([hashg1list(g_vec), roothash])
        x = ZR.hash(transcript)
        xi = x ** -1
        # this part must come after the challenge is generated, which must
        # come after L and R are calculated. Don't try to condense the loops
        g_vec_p, a_vecs_p = [], []
        b_vecs_p = [[] for _ in range(len(b_vecs))]
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i].pow(xi) * g_vec[n_p:][i].pow(x))
        for k in range(len(a_vecs)):
            a_vecs_p.append([])
            for i in range(n_p):
                a_vecs_p[k].append(a_vecs[k][:n_p][i] * x + a_vecs[k][n_p:][i] * xi)
        for j in range(len(b_vecs)):
            #for i in range(n_p):
            #    b_vecs_p[j].append(b_vecs[j][:n_p][i] * xi + b_vecs[j][n_p:][i] * x)
            b_vecs_p[j] = [b_vecs[j][:n_p][i] * xi + b_vecs[j][n_p:][i] * x for i in range(n_p)]
        x2, xi2 = x * x, xi * xi
        Lax2Raxi2s = [Las[i].pow(x2) * Ras[i].pow(xi2) for i in range(len(a_vecs))]
        #for i in range(numproofs // row_length):
        #    for j in range(row_length):
        #        abs_idx = i * row_length + j
        #        P_vec[abs_idx] *= Lax2Raxi2s[i] * u ** (x2 * cl_vec[abs_idx] + xi2 * cr_vec[abs_idx])
        xil = [x2, xi2]
        for i in range(numproofs):
            upow = inner_product(xil, [cl_vec[i], cr_vec[i]])
            P_vec[i] *= Lax2Raxi2s[i//row_length] * u.pow(upow)
        proofs = recursive_proofs(g_vec_p, a_vecs_p, b_vecs_p, u, n_p, P_vec, transcript)
        for j in range(len(proofs)):
            proofsteps[j].append(L_vec[j])
            proofsteps[j].append(R_vec[j])
            proofs[j].append(proofsteps[j])
        return proofs

    t = len(a_vecs[0])
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, u] = crs
        g_vec = g_vec[:t]
    if comms is None:
        comms = []
        for j in range(len(a_vecs)):
            comms.append(G1.identity())
            for i in range(t):
                comms[j] *= g_vec[i].pow(a_vecs[j][i])

    iprods = [ZR(0) for _ in range(len(b_vecs)*len(a_vecs))]
    P_vecs = [None] * (len(b_vecs) * len(a_vecs))

    row_length = len(b_vecs)
    for i in range(len(a_vecs)):
        for j in range(len(b_vecs)):
            abs_idx = i * row_length + j
            #for k in range(t):
            #    iprods[abs_idx] += a_vecs[i][k] * b_vecs[j][k]
            iprods[abs_idx] = inner_product(a_vecs[i], b_vecs[j])
            P_vecs[abs_idx] = comms[i] * u.pow(iprods[abs_idx])
    transcript = pickle.dumps(u)
    proofsize = len(a_vecs) * len(b_vecs)
    i = 0
    proofs = recursive_proofs(g_vec, a_vecs, b_vecs, u, t, P_vecs, transcript)
    for j in range(len(proofs)):
        proofs[j].insert(0, t)
    # Transform the proofs into a list of lists
    proofs_p = []
    for i in range(len(a_vecs)):
        proofs_p.append([])
        for j in range(len(proofs)//len(a_vecs)):
            proofs_p[i].append(proofs[i*(len(proofs)//len(a_vecs))+j])
    return [comms, iprods, proofs_p]


# Verify multiple inner product arguments (with one vector known) that was generated in a batch
def verify_double_batch_inner_product_one_known(comms, iprods, b_vec, proofs, crs=None):
    def recursive_verify(g_vec, b_vec, u, proofs, n, Ps, transcript):
        if n == 1:
            ret = True
            for i in range(len(proofs)):
                a, b = proofs[i][0][0], b_vec[0]
                ret &= Ps[i] == g_vec[0].pow(a) * u.pow(a * b)
            return ret
        Ls = []
        Rs = []
        branches = []
        last_roothash = None
        if n % 2 == 1:
            for i in range(len(proofs)):
                [na, roothash, branch, L, R] = proofs[i][-1]
                Ps[i] *= g_vec[-1].pow(na) * u.pow(na * b_vec[-1])
                Ls.append(L)
                Rs.append(R)
                branches.append(branch)
                if i!=0:
                    assert last_roothash == roothash
                else:
                    last_roothash = roothash
        else:
            for i in range(len(proofs)):
                [roothash, branch, L, R] = proofs[i][-1]
                Ls.append(L)
                Rs.append(R)
                branches.append(branch)
                if i!=0:
                    assert last_roothash == roothash
                else:
                    last_roothash = roothash

        for i in range(len(proofs)):
            leafi = hash_list_to_bytes(
                [hashzrlist(b_vec), hashg1list([Ps[i], Ls[i], Rs[i]])]
            )
            if not MerkleTree.verify_membership(
                leafi, branches[i], last_roothash
            ):
                return False
        transcript += pickle.dumps([hashg1list(g_vec), last_roothash])
        x = ZR.hash(transcript)
        xi = x ** -1
        x2 = x*x
        xi2 = xi*xi
        n_p = n // 2
        g_vec_p = []
        b_vec_p = []
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i].pow(xi) * g_vec[n_p:][i].pow(x))
            b_vec_p.append(b_vec[:n_p][i] * xi + b_vec[n_p:][i] * x)
        Ps_p = []
        for i in range(len(proofs)):
            Ps_p.append(Ls[i] ** (x2) * Ps[i] * Rs[i] ** (xi2))
        proofs_p = []
        for i in range(len(proofs)):
            proofs_p.append(proofs[i][:-1])
        return recursive_verify(g_vec_p, b_vec_p, u, proofs_p, n_p, Ps_p, transcript)

    n = proofs[0][0]
    iproofs = []
    for i in range(len(proofs)):
        iproofs.append(proofs[i][1:])
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, u] = crs
        g_vec = g_vec[:n]
    Ps = []
    for i in range(len(comms)):
        Ps.append(comms[i] * u.pow(iprods[i]))
    transcript = pickle.dumps(u)
    return recursive_verify(g_vec, b_vec, u, iproofs, n, Ps, transcript)


def prove_double_batch_inner_product_one_known_but_different(a_vecs, b_vecs, comms=None, crs=None):
    def recursive_proofs(g_vec, a_vecs, b_vecs, u, n, P_vec, transcript):
        #row_length = len(b_vecs)//len(a_vecs)
        numproofs = len(a_vecs) * len(b_vecs)
        row_length = numproofs//len(a_vecs)
        col_length = numproofs//len(b_vecs)
        numverifiers = len(b_vecs)
        numpolys = len(a_vecs)
        _ = [g.preprocess(5) for g in g_vec]
        if n == 1:
            #proofs = [None] * numproofs
            #for i in range(len(proofs) // row_length):
            #    for j in range(row_length):
            #        abs_idx = i * row_length + j
            #        proofs[abs_idx] = [[a_vecs[i][0]]]
            #return proofs
            proofs = [ [ [] for _ in range(numpolys)] for _ in range(numverifiers)]
            for i in range(numpolys):
                for j in range(numverifiers):
                    proofs[j][i] = [[a_vecs[i][0]]]
            #proofs = [[a_vecs[:][0]]] * numverifiers
            return proofs
        #proofsteps = [[] for _ in range(numproofs)]
        proofsteps = [ [ [] for _ in range(numpolys)] for _ in range(numverifiers)]
        if n % 2 == 1:
            for i in range(numpolys):
                na = a_vecs[i][-1] * -1
                gtail = g_vec[-1].pow(na)
                for j in range(numverifiers):
                    #abs_idx = i * row_length + j
                    #P_vec[abs_idx] *= gtail * u.pow(na * b_vecs[j][-1])
                    P_vec[j][i] *= gtail * u.pow(na * b_vecs[j][-1])
                    #proofsteps[abs_idx].append(na)
                    proofsteps[j][i].append(na)
        n_p = n // 2
        #cl_vec = [0 for _ in range(len(P_vecs))]
        #cr_vec = [0 for _ in range(len(P_vecs))]
        #L_vec = [None] * len(P_vecs)
        #R_vec = [None] * len(P_vecs)
        cl_vec = [ [ 0 for _ in range(numpolys)] for _ in range(numverifiers)]
        cr_vec = [ [ 0 for _ in range(numpolys)] for _ in range(numverifiers)]
        L_vec = [ [ [] for _ in range(numpolys)] for _ in range(numverifiers)]
        R_vec = [ [ [] for _ in range(numpolys)] for _ in range(numverifiers)]
        Las = [G1.identity() for _ in range(len(a_vecs))]
        Ras = [G1.identity() for _ in range(len(a_vecs))]
        for j in range(len(a_vecs)):
            for i in range(n_p):
                Las[j] *= g_vec[n_p:][i].pow(a_vecs[j][:n_p][i])
                Ras[j] *= g_vec[:n_p][i].pow(a_vecs[j][n_p:][i])
        for i in range(numpolys):
            for j in range(numverifiers):
                #abs_idx = i * numverifiers + j
                #cl_vec[abs_idx] = inner_product(a_vecs[i][:n_p], b_vecs[j][n_p:2*n_p])
                #cr_vec[abs_idx] = inner_product(a_vecs[i][n_p:2*n_p], b_vecs[j][:n_p])
                #L_vec[abs_idx] = Las[i] * (u.pow(cl_vec[abs_idx]))
                #R_vec[abs_idx] = Ras[i] * (u.pow(cr_vec[abs_idx]))
                cl_vec[j][i] = inner_product(a_vecs[i][:n_p], b_vecs[j][n_p:2*n_p])
                cr_vec[j][i] = inner_product(a_vecs[i][n_p:2*n_p], b_vecs[j][:n_p])
                L_vec[j][i] = Las[i] * (u.pow(cl_vec[j][i]))
                R_vec[j][i] = Ras[i] * (u.pow(cr_vec[j][i]))
        # Fiat Shamir
        # Make a merkle tree over everything that varies between verifiers
        # TODO: na should be in the transcript
        tree = MerkleTree()
        b_hashes = [hashzrlist(b_vecs[i]) for i in range(len(b_vecs))]
        leaves = [hash_list_to_bytes(
            #[b_hashes[j%len(b_vecs)], hashg1list([P_vec[j], L_vec[j], R_vec[j]])]
            [b_hashes[j%len(b_vecs)], hashg1list([P_vec[j%numverifiers][j//numverifiers], L_vec[j%numverifiers][j//numverifiers], R_vec[j%numverifiers][j//numverifiers]])]
            ) for j in range(numproofs)]
        tree.append_many(leaves)
        roothash = tree.get_root_hash()
        #for j in range(len(P_vecs)):
        #    branch = tree.get_branch(j)
        #    proofsteps[j].append(roothash)
        #    proofsteps[j].append(branch)
        for i in range(numpolys):
            for j in range(numverifiers):
                branch = tree.get_branch(i * numverifiers + j)
                proofsteps[j][i].append(roothash)
                proofsteps[j][i].append(branch)
        transcript += pickle.dumps([hashg1list(g_vec), roothash])
        x = ZR.hash(transcript)
        xi = x ** -1
        # this part must come after the challenge is generated, which must
        # come after L and R are calculated. Don't try to condense the loops
        g_vec_p, a_vecs_p = [], []
        b_vecs_p = [[] for _ in range(len(b_vecs))]
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i].pow(xi) * g_vec[n_p:][i].pow(x))
        for k in range(len(a_vecs)):
            a_vecs_p.append([])
            for i in range(n_p):
                a_vecs_p[k].append(a_vecs[k][:n_p][i] * x + a_vecs[k][n_p:][i] * xi)
        for j in range(len(b_vecs)):
            #for i in range(n_p):
            #    b_vecs_p[j].append(b_vecs[j][:n_p][i] * xi + b_vecs[j][n_p:][i] * x)
            b_vecs_p[j] = [b_vecs[j][:n_p][i] * xi + b_vecs[j][n_p:][i] * x for i in range(n_p)]
        x2, xi2 = x * x, xi * xi
        Lax2Raxi2s = [Las[i].pow(x2) * Ras[i].pow(xi2) for i in range(len(a_vecs))]
        #for i in range(numproofs // row_length):
        #    for j in range(row_length):
        #        abs_idx = i * row_length + j
        #        P_vec[abs_idx] *= Lax2Raxi2s[i] * u ** (x2 * cl_vec[abs_idx] + xi2 * cr_vec[abs_idx])
        xil = [x2, xi2]
        #for i in range(numproofs):
        #    upow = inner_product(xil, [cl_vec[i], cr_vec[i]])
        #    P_vec[i] *= Lax2Raxi2s[i//row_length] * u.pow(upow)
        for i in range(numpolys):
            for j in range(numverifiers):
                upow = inner_product(xil, [cl_vec[j][i], cr_vec[j][i]])
                P_vec[j][i] *= Lax2Raxi2s[i] * u.pow(upow)
        proofs = recursive_proofs(g_vec_p, a_vecs_p, b_vecs_p, u, n_p, P_vec, transcript)
        #for j in range(len(proofs)):
        #    proofsteps[j].append(L_vec[j])
        #    proofsteps[j].append(R_vec[j])
        #    proofs[j].append(proofsteps[j])
        for j in range(len(proofs)):
            for i in range(len(proofs[0])):
                proofsteps[j][i].append(L_vec[j][i])
                proofsteps[j][i].append(R_vec[j][i])
                proofs[j][i].append(proofsteps[j][i])
        return proofs

    t = len(a_vecs[0])
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, u] = crs
        g_vec = g_vec[:t]
    if comms is None:
        comms = []
        for j in range(len(a_vecs)):
            comms.append(G1.identity())
            for i in range(t):
                comms[j] *= g_vec[i].pow(a_vecs[j][i])

    #iprods = [ZR(0) for _ in range(len(b_vecs)*len(a_vecs))]
    #P_vecs = [None] * (len(b_vecs) * len(a_vecs))
    numverifiers = len(b_vecs)
    numpolys = len(a_vecs)
    iprods = [ [ 0 for _ in range(numpolys)] for _ in range(numverifiers)]
    P_vecs = [ [ [] for _ in range(numpolys)] for _ in range(numverifiers)]

    row_length = len(b_vecs)
    for i in range(len(a_vecs)):
        for j in range(len(b_vecs)):
            #abs_idx = i * row_length + j
            iprods[j][i] = inner_product(a_vecs[i], b_vecs[j])
            P_vecs[j][i] = comms[i] * u.pow(iprods[j][i])
            #iprods[abs_idx] = inner_product(a_vecs[i], b_vecs[j])
            #P_vecs[abs_idx] = comms[i] * u.pow(iprods[abs_idx])
    transcript = pickle.dumps(u)
    i = 0
    proofs = recursive_proofs(g_vec, a_vecs, b_vecs, u, t, P_vecs, transcript)
    #for j in range(len(proofs)):
    #    proofs[j].insert(0, t)


    for i in range(len(a_vecs)):
        for j in range(len(b_vecs)):
            proofs[j][i].insert(0,t)
    
    #this line switches the indices of the list
    invproofs = [list(a) for a in zip(*proofs)]
    return [comms, iprods, invproofs]

#@profile
def prove_double_batch_inner_product_one_known_but_differenter(a_vecs, b_vecs, comms=None, crs=None):
    #@profile
    def recursive_proofs(g_vec, a_vecs, b_vecs, u, n, P_vec, transcript):
        numverifiers = len(b_vecs)
        numpolys = len(a_vecs)
        numproofs = numverifiers * numpolys
        _ = [g.preprocess(5) for g in g_vec]
        if n == 1:
            treeparts = [ [] for j in range(numverifiers) ]
            proofs = [ [ [[a_vecs[i][0]]] for i in range(numpolys)] for _ in range(numverifiers)]
            return [proofs, treeparts]
        proofsteps = [ [ [] for _ in range(numpolys)] for _ in range(numverifiers)]
        nas = None
        if n % 2 == 1:
            for i in range(numpolys):
                na = a_vecs[i][-1] * -1
                gtail = g_vec[-1].pow(na)
                for j in range(numverifiers):
                    P_vec[j][i] *= gtail * u.pow(na * b_vecs[j][-1])
            #        proofsteps[j][i].append(na)
            nas = [a_vecs[i][-1] * -1 for i in range(numpolys)]
            proofsteps = [ [ [nas[i]] for i in range(numpolys)] for j in range(numverifiers)]
            
        n_p = n // 2
        #cl_vec = [ [ 0 for _ in range(numpolys)] for _ in range(numverifiers)]
        #cr_vec = [ [ 0 for _ in range(numpolys)] for _ in range(numverifiers)]
        #L_vec = [ [ [] for _ in range(numpolys)] for _ in range(numverifiers)]
        #R_vec = [ [ [] for _ in range(numpolys)] for _ in range(numverifiers)]
        Las = [G1.identity() for _ in range(len(a_vecs))]
        Ras = [G1.identity() for _ in range(len(a_vecs))]
        for j in range(len(a_vecs)):
            for i in range(n_p):
                Las[j] *= g_vec[n_p:][i].pow(a_vecs[j][:n_p][i])
                Ras[j] *= g_vec[:n_p][i].pow(a_vecs[j][n_p:][i])
        #for i in range(numpolys):
        #    for j in range(numverifiers):
        #        cl_vec[j][i] = inner_product(a_vecs[i][:n_p], b_vecs[j][n_p:2*n_p])
        #        cr_vec[j][i] = inner_product(a_vecs[i][n_p:2*n_p], b_vecs[j][:n_p])
        #        L_vec[j][i] = Las[i] * (u.pow(cl_vec[j][i]))
        #        R_vec[j][i] = Ras[i] * (u.pow(cr_vec[j][i]))
        cl_vec = [ [ inner_product(a_vecs[i][:n_p], b_vecs[j][n_p:2*n_p]) for i in range(numpolys)] for j in range(numverifiers)]
        cr_vec = [ [ inner_product(a_vecs[i][n_p:2*n_p], b_vecs[j][:n_p]) for i in range(numpolys)] for j in range(numverifiers)]
        L_vec = [ [ Las[i] * (u.pow(cl_vec[j][i])) for i in range(numpolys)] for j in range(numverifiers)]
        R_vec = [ [ Ras[i] * (u.pow(cr_vec[j][i])) for i in range(numpolys)] for j in range(numverifiers)]
        # Fiat Shamir
        # Make a merkle tree over everything that varies between verifiers
        # TODO: na should be in the transcript
        tree = MerkleTree()
        if nas is None:
            zr_hashes = [hashzrlist(b_vecs[i]) for i in range(len(b_vecs))]
        else:
            zr_hashes = [hashzrlist(b_vecs[i] + nas) for i in range(len(b_vecs))]
        g1lists = [ [] for j in range(numverifiers) ]
        for j in range(numverifiers):
            #smash each list of lists into a single list (list() causes the map operation to execute)
            _ = list(map(g1lists[j].extend, [P_vec[j], L_vec[j], R_vec[j]]))
        leaves = [pickle.dumps(
                [zr_hashes[j], hashg1listbn(g1lists[j])]
            ) for j in range(numverifiers)]
        tree.append_many(leaves)
        roothash = tree.get_root_hash()
        treesteps = [ [roothash, tree.get_branch(j)] for j in range(numverifiers)]
        transcript += pickle.dumps([hashg1list(g_vec), roothash])
        x = ZR.hash(transcript)
        xi = x ** -1
        # this part must come after the challenge is generated, which must
        # come after L and R are calculated. Don't try to condense the loops
        g_vec_p, a_vecs_p = [], []
        b_vecs_p = [[] for _ in range(len(b_vecs))]
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i].pow(xi) * g_vec[n_p:][i].pow(x))
        for k in range(len(a_vecs)):
            a_vecs_p.append([])
            for i in range(n_p):
                a_vecs_p[k].append(a_vecs[k][:n_p][i] * x + a_vecs[k][n_p:][i] * xi)
        for j in range(len(b_vecs)):
            b_vecs_p[j] = [b_vecs[j][:n_p][i] * xi + b_vecs[j][n_p:][i] * x for i in range(n_p)]
        x2, xi2 = x * x, xi * xi
        Lax2Raxi2s = [Las[i].pow(x2) * Ras[i].pow(xi2) for i in range(len(a_vecs))]
        xil = [x2, xi2]
        # the following line is equivalent to:
        # for i in range(numpolys):
        #    for j in range(numverifiers):
        #        upow = inner_product(xil, [cl_vec[j][i], cr_vec[j][i]])
        #        P_vec[j][i] *= Lax2Raxi2s[i] * u.pow(upow)
        _ = [ [P_vec[j][i].__imul__(Lax2Raxi2s[i] * u.pow(inner_product(xil, [cl_vec[j][i], cr_vec[j][i]]))) for i in range(numpolys)] for j in range(numverifiers)]
        proofs, treeparts = recursive_proofs(g_vec_p, a_vecs_p, b_vecs_p, u, n_p, P_vec, transcript)
        for j in range(len(proofs)):
            treeparts[j].append(treesteps[j])
            #for i in range(len(proofs[0])):
            #    proofs[j][i].append(proofsteps[j][i] + [L_vec[j][i]] + [R_vec[j][i]])
        _ = [ [ proofs[j][i].append(proofsteps[j][i] + [L_vec[j][i]] + [R_vec[j][i]]) for i in range(numpolys)] for j in range(numverifiers)]
        return [proofs, treeparts]

    t = len(a_vecs[0])
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, u] = crs
        g_vec = g_vec[:t]
    if comms is None:
        comms = []
        for j in range(len(a_vecs)):
            comms.append(G1.identity())
            _ = [ comms[j].__imul__(g_vec[i].pow(a_vecs[j][i])) for i in range(t) ]
            #for i in range(t):
            #    comms[j] *= g_vec[i].pow(a_vecs[j][i])


    numverifiers = len(b_vecs)
    numpolys = len(a_vecs)
    iprods = [ [ inner_product(a_vecs[i], b_vecs[j]) for i in range(numpolys)] for j in range(numverifiers)]
    P_vecs = [ [ comms[i] * u.pow(iprods[j][i]) for i in range(numpolys)] for j in range(numverifiers)]

    transcript = pickle.dumps(u)
    proofs, treeparts = recursive_proofs(g_vec, a_vecs, b_vecs, u, t, P_vecs, transcript)

    outproofs = [ [proofs[j], treeparts[j]] for j in range(numverifiers)]
    
    return [comms, iprods, outproofs]

#@profile
def verify_double_batch_inner_product_one_known_but_differenter(comms, iprods, b_vec, proofs, treeparts, crs=None):
    #@profile
    def recursive_verify(g_vec, b_vec, u, proofs, treeparts, n, Ps, transcript):
        if n == 1:
            ret = True
            g_vec[0].preprocess(4)
            for i in range(len(proofs)):
                try:
                   a, b = proofs[i][0][0], b_vec[0]
                except ValueError:
                    return False
                ret &= Ps[i] == g_vec[0].pow(a) * u.pow(a * b)
            return ret
        Ls, Rs = [], []
        nas = None
        if n % 2 == 1:
            nas = []
            g_vec[-1].preprocess(4)
            for i in range(len(proofs)):
                #[na, roothash, branch, L, R] = proofs[i][-1]
                try:
                    [na, L, R] = proofs[i][-1]
                except ValueError:
                    return False
                Ps[i] *= g_vec[-1].pow(na) * u.pow(na * b_vec[-1])
                Ls.append(L)
                Rs.append(R)
                nas.append(na)
        else:
            for i in range(len(proofs)):
                #[roothash, branch, L, R] = proofs[i][-1]
                try:
                    [L, R] = proofs[i][-1]
                except ValueError:
                    return False
                Ls.append(L)
                Rs.append(R)
        try:
            roothash, branch = treeparts[-1]
        except ValueError:
            return False
        g1list = []
        _ = list(map(g1list.extend, [Ps, Ls, Rs]))
        if nas is None:
            leaf = pickle.dumps([hashzrlist(b_vec), hashg1listbn(g1list)])
        else:
            leaf = pickle.dumps([hashzrlist(b_vec + nas), hashg1listbn(g1list)])
        if not MerkleTree.verify_membership(leaf, branch, roothash):
            return False
        transcript += pickle.dumps([hashg1listbn(g_vec), roothash])
        x = ZR.hash(transcript)
        xi = x ** -1
        x2 = x*x
        xi2 = xi*xi
        n_p = n // 2
        g_vec_p = [g_vec[:n_p][i].pow(xi) * g_vec[n_p:][i].pow(x) for i in range(n_p)]
        b_vec_p = [b_vec[:n_p][i] * xi + b_vec[n_p:][i] * x for i in range(n_p)]
        Ps_p = [ Ls[i].pow(x2) * Ps[i] * Rs[i].pow(xi2) for i in range(len(proofs))]
        proofs_p = [proofs[i][:-1] for i in range(len(proofs))]
        treeparts_p = treeparts[:-1]
        return recursive_verify(g_vec_p, b_vec_p, u, proofs_p, treeparts_p, n_p, Ps_p, transcript)

    n = len(b_vec)
    iproofs = []
    for i in range(len(proofs)):
        iproofs.append(proofs[i][1:])
    if crs is None:
        g_vec = G1.hash_many(b"honeybadgerg", n)
        u = G1.hash(b"honeybadgeru")
    else:
        [g_vec, u] = crs
        g_vec = g_vec[:n]
    Ps = [comms[i] * u.pow(iprods[i]) for i in range(len(comms))]
    #for i in range(len(comms)):
    #    Ps.append(comms[i] * u.pow(iprods[i]))
    transcript = pickle.dumps(u)
    return recursive_verify(g_vec, b_vec, u, proofs, treeparts, n, Ps, transcript)