from pytest import mark
from adkg.polynomial import polynomials_over
from adkg.acss_dcr import ACSS_DCR
from pickle import dumps, loads
# from pypairing import Curve25519G as G1, Curve25519ZR as ZR, curve25519multiexp as multiexp
from pypairing import G1, ZR, blsmultiexp as multiexp

def get_avss_params(n, G1):
    from phe import PaillierPublicKey, PaillierPrivateKey
    g, h = G1.hash(b'g'), G1.hash(b'h') 
    public_keys = [None for _ in range(n)]
    private_keys = [None for _ in range(n)]
    with open("apps/tutorial/keys", 'r') as kfile:
        keys = kfile.readlines()
        for i in range(n):
            data = keys[i].split(' ')
            public_keys[i] = PaillierPublicKey(int(data[0]))
            private_keys[i] = PaillierPrivateKey(public_keys[i], int(data[1]), int(data[2]))
    return g, h, public_keys, private_keys

def gen_dual_code(n, degree, poly):
    def get_vi(i, n):
        out = ZR(1)
        for j in range(1, n+1):
            if j != i:
                out = out / (i-j)
        return out
    q = poly.random(n -degree -2)
    q_evals = [q(i+1) for i in range(n)]
    return [q_evals[i] * get_vi(i+1, n) for i in range(n)]
    

@mark.parametrize(
    "t, deg, n",
    [
        (5, 10, 16),
        (10, 21, 32),
        (21, 42, 64),
        (42, 85, 128),
    ])
def test_benchmark_acss_dcr_dealer(benchmark, t, deg, n):
    g, h, pks, sks = get_avss_params(n, G1)
    secret = ZR.rand()
    poly = polynomials_over(ZR)
    poly.clear_cache()
    benchmark(_get_dealer_msg, secret, pks, g, t, deg, n, poly)

@mark.parametrize(
    "t, deg, n",
    [
        (5, 10, 16),
        (10, 21, 32),
        (21, 42, 64),
        (42, 85, 128),
    ])
def test_benchmark_acss_dcr_receiver(benchmark, t, deg, n):
    secret = ZR.rand()
    poly = polynomials_over(ZR)
    g, _, pks, sks = get_avss_params(n, G1)
    msgs = _get_dealer_msg(secret, pks, g, t, deg, n, poly)
    dual_codes = {}
    dual_codes[(deg,n)] = gen_dual_code(n,deg,poly)
    benchmark( _handle_dealer_msg, msgs, g, t, deg, n, dual_codes, poly, pks, sks)
    
def _handle_dealer_msg(dealer_msg, g, t, deg, n, dual_codes, poly, pks, sks):
    poly.clear_cache()
    for idx in range(n):
        sk = sks[idx]
        comms, encryptions, proofs = loads(dealer_msg)
        #Check 1: verify that polynomial is degree d
        if not check_degree(deg, comms, dual_codes, poly):
            print("Degree check failed")
        
        #Check 2: check each encryption proof is valid
        for i in range(n):
            if not verify_knowledge_of_discrete_log(pks[i], g, comms[i], encryptions[i], proofs[i]):
                print("Verify Knowledge failed")
        
        sk.raw_decrypt(encryptions[idx])

def _get_dealer_msg(secret, pks, g, t, deg, n, poly):
    poly.clear_cache()
    phi = poly.random(deg, secret)
    outputs = [prove_knowledge_of_encrypted_dlog(g, phi(i+1), pks[i]) for i in range(n)]
    return dumps([[outputs[i][j] for i in range(n)] for j in range(3)])


def prove_knowledge_of_encrypted_dlog(g, x, pk, g_to_the_x=None):
    if g_to_the_x is None:
        Y = g**x
    else:
        Y = g_to_the_x
    r = pk.get_random_lt_n()
    c = pk.encrypt(int(x), r_value=r).ciphertext(be_secure=False)
    # Todo: see if this limitation is libarary-specific. Maybe use a slightly larget N? 
    u = pk.get_random_lt_n() // 3 # maximum valid value we can encrypt
    T = g ** ZR(u)

    e = ZR.hash(dumps([pk, g, Y, c, T]))
    z = u + int(e)*int(x)
    s = pk.get_random_lt_n()
    e_u = pk.encrypt(u, r_value=s)
    w = (pow(r, int(e), pk.nsquare) * s) % pk.nsquare
    proof = [T, z, e_u, w]
    return [Y, c, proof]

def verify_knowledge_of_discrete_log(pk, g, Y, c, proof):
    T, z, e_u, w = proof
    e = ZR.hash(dumps([pk, g, Y, c, T]))
    # be_secure is default true and adds a randomizing factor to the ciphertext as a failsafe. 
    # we need it turned off so that the calculations will be correct
    c_e = pow(c, int(e), pk.nsquare)
    return T == (g ** z) * (Y ** (-e)) and (e_u.ciphertext(be_secure=False) * c_e) % pk.nsquare == pk.encrypt(z, r_value=w).ciphertext(be_secure=False)


def check_degree(claimed_degree, commitments, dual_codes, poly):
    if (claimed_degree, len(commitments)) not in dual_codes.keys():
        dual_codes[(claimed_degree, len(commitments))] = gen_dual_code(len(commitments), claimed_degree, poly)

    dual_code = dual_codes[(claimed_degree, len(commitments))]
    check = multiexp(commitments, dual_code)

    return check == G1.rand() ** 0
