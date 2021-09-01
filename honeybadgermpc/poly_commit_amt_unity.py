from pypairing import ZR, G1, G2, pair
from honeybadgermpc.polynomial import polynomials_over
from math import log, ceil

def get_all_roots_of_unity(n):
    #get smallest power of two greater than or equal to N
    N = 2 ** ceil(log(n,2))
    #hardcoded value for bls12-381. modulus = 2^s * t + 1
    s = 32
    omega = ZR.root_of_unity()
    for i in range(s, ceil(log(n,2)), -1):
        omega *= ZR.root_of_unity()
    omegas = [ZR(1), omega]
    for i in range(2,n):
        omegas.append(omegas[i-1]*omega)
    return omegas

def bit_reverse(i, length):
    r = 0
    for _ in range(length):
       r *= 2
       r += i%2
       i = i // 2
    return r
    
def gen_accumulator_tree(n):
    omegas = get_all_roots_of_unity(n)
    #tree is a list of lists, where tree[i][j] is the j'th leaf in the i'th row (bottom row is row 0)
    numlevels = ceil(log(n,2)) + 1
    tree = [2**i * [None] for i in reversed(range(numlevels))]
    poly = polynomials_over(ZR)
    for i in range(len(omegas)):
        tree[0][bit_reverse(i, numlevels-1)] = poly([ZR(-1) * omegas[i], ZR(1)])
    for k in range(1, numlevels):
        for i in range(len(tree[k])):
            tree[k][i] = tree[k - 1][2*i] * tree[k - 1][2*i + 1]
    return tree

def gen_multipoint_eval_tree(poly, acctree):
    numlevels = len(acctree)
    tree = [2**i * [None] for i in reversed(range(numlevels))]
    rootquotient = poly / acctree[numlevels-1][0]
    #obviously a slow way to get the remainder
    rootremainder = poly - (rootquotient * acctree[numlevels-1][0])
    tree[numlevels-1][0] = [rootquotient, rootremainder]
    #normally the first row in the tree structure is the largest one
    prevrow = []
    for k in reversed(range(len(tree)-1)):
        for i in range(len(tree[k])):
            q = tree[k+1][i//2][1] / acctree[k][i]
            r = tree[k+1][i//2][1] - (acctree[k][i] * q)
            tree[k][i] = [q,r]
    return tree

#commit to every quotient polynomial in the eval tree
def commit_eval_tree(evaltree, g1s):
    numlevels = len(evaltree)
    committree = [2**i * [None] for i in reversed(range(numlevels))]
    for k in range(len(evaltree)):
        for i in range(len(evaltree[k])):
            qpoly = evaltree[k][i][0]
            c = G1.identity()
            #this is a multiexponentiation
            for j in range(len(qpoly.coeffs)):
                c *= g1s[j]**qpoly.coeffs[j]
            committree[k][i] = c
    return committree

#commit to every accumulator polynomial in the acc tree
def commit_acc_tree(acctree, crs):
    g2s = crs[1]
    numlevels = len(acctree)
    committree = [2**i * [None] for i in reversed(range(numlevels))]
    for k in range(len(acctree)):
        for i in range(len(acctree[k])):
            poly = acctree[k][i]
            c = G2.identity()
            #this is a multiexponentiation
            for j in range(len(poly.coeffs)):
                c *= g2s[j]**poly.coeffs[j]
            committree[k][i] = c
    return committree

#get the contents of the path that leads to (and includes) the specified leaf
def get_tree_branch(tree, leafid):
    branch = []
    for k in range(len(tree)):
        branch.append(tree[k][leafid])
        leafid = leafid // 2
    return branch

def gen_crs(degree_max=32, alpha=None):
    if alpha is None:
        alpha = ZR.rand()
    g1g = G1.hash(b"honeybadgerg1g")
    g2g = G2.hash(b"honeybadgerg2g")
    exp = ZR(1)
    g1s = [g1g]
    g2s = [g2g]
    for i in range(degree_max):
        exp *= alpha
        g1s.append(g1g**exp)
        g2s.append(g2g**exp)
    return [g1s, g2s]

class PolyCommitAMTUnity:
    def __init__(self, crs, n):
        self.g1s = crs[0]
        self.g2s = crs[1]
        self.n = n
        self.omegas = get_all_roots_of_unity(n)
        self.acctree = gen_accumulator_tree(n)
        self.comacctree = commit_acc_tree(self.acctree, crs)
        self.evaltree = None
        self.comevaltree = None

    def commit(self, phi):
        c = G1.identity()
        for j in range(len(phi.coeffs)):
            c *= self.g1s[j]**phi.coeffs[j]
        return c

    def create_witness(self, phi, i):
        if self.evaltree is None:
            self.evaltree = gen_multipoint_eval_tree(phi, self.acctree)
        if self.comevaltree is None:
            self.comevaltree = commit_eval_tree(self.evaltree, self.g1s)
        branch = get_tree_branch(self.comevaltree, bit_reverse(i, ceil(log(self.n,2))))
        #if n is bigger than the length of the polynomial, the witness will end up having unneeded elements
        while branch[-1] == G1.identity():
            branch = branch[:-1]
        return branch
    
    def batch_create_witness(self, phi):
        if self.evaltree is None:
            self.evaltree = gen_multipoint_eval_tree(phi, self.acctree)
        if self.comevaltree is None:
            self.comevaltree = commit_eval_tree(self.evaltree, self.g1s)
        branches = [get_tree_branch(self.comevaltree, bit_reverse(i, ceil(log(self.n,2)))) for i in range(self.n)]
        for i in range(len(branches)):
            while branches[i][-1] == G1.identity():
                branches[i] = branches[i][:-1]
        return branches

    def verify_eval(self, c, i, phi_at_omega_i, witness):
        valcom = self.g1s[0]**phi_at_omega_i
        valcom.negate()
        lhs = pair(c*valcom, self.g2s[0])
        rhs = pair(G1.identity(), G2.identity())
        acc_branch = get_tree_branch(self.comacctree, bit_reverse(i, ceil(log(self.n,2))))
        #if witness is shorter (due to more than degree + 1 recipients), it will only
        #check as many entries as are in witness, which is what we want
        for items in zip(witness, acc_branch):
            rhs = rhs * pair(items[0], items[1])
        return lhs == rhs        
        
        