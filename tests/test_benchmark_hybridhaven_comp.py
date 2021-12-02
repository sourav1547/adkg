from pytest import mark
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_bulletproof_blind import PolyCommitBulletproofBlind
from honeybadgermpc.poly_commit_hybrid import PolyCommitHybrid
from honeybadgermpc.haven import HavenAVSS, HybridHavenAVSS
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.utils.misc import print_exception_callback
from honeybadgermpc.utils.serializer import serialize, deserialize
import hashlib
from pypairing import G1 as group, ZR as field
# from pypairing import Curve25519G as group, Curve25519ZR as field

class HavenMessageType:
    ECHO = 1
    READY = 2
    SEND = 3

def get_avss_params(n, t):
    gs = group.hash_many(b"honeybadgerg", 2*t+1)
    hs = group.hash(b"honeybadgerh")
    u = group.hash(b"honeybadgeru")
    crs = [gs, hs, u]
    g, h = gs[0], group.hash(b'h')   
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = field.hash(bytes(i))
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys, crs

@mark.parametrize(
    "t, p, n",
    [
        (5, 10, 7),
    ])
def test_benchmark_hybrid_haven_dealer(benchmark, t, p, n):
    value = field.rand()
    poly = polynomials_over(field)
    _, _, _, _, crs = get_avss_params(n, t)
    pc = PolyCommitBulletproofBlind(crs, 2*t, group=group)
    pc2 = PolyCommitHybrid(crs, 2*t, group=group)
    benchmark(_get_dealer_msg, value, t, p, n, poly, pc, pc2, field, group)

@mark.parametrize(
    "t, p, n",
    [
        (5, 10, 7),
    ])
def test_benchmark_hybrid_haven_receiver(benchmark, t, p, n):
    value = field.rand()
    poly = polynomials_over(field)
    _, _, _, _, crs = get_avss_params(n, t)
    pc = PolyCommitBulletproofBlind(crs, 2*t, group=group)
    pc2 = PolyCommitHybrid(crs, 2*t, group=group)
    msgs = _get_dealer_msg(value, t, p, n, poly, pc, pc2, field, group)
    benchmark( _handle_dealer_msg, msgs[0], t, p, n, 0, pc, pc2, field, group)
    
def _handle_dealer_msg(dealer_msg, t, p, n, my_id, poly_commit, poly_commit2, field, group):
    try:
        (C, R_Com, S_Com_list, S_Com_proofs_i, T_proofs, y_list_i) = dealer_msg
    except Exception:
        return

    vector = R_Com[0:2] + [S_Com_list]
    datab = bytearray()
    for item in vector:
        datab.extend(serialize(item))
    C_local = hashlib.sha256(datab).digest() 
    if not C_local == C:
        return
    
    for j in range(n):
        if not poly_commit.verify_eval(S_Com_list[j], my_id+1, y_list_i[j], S_Com_proofs_i[j]):
            return
    
    if not poly_commit2.verify_commit(R_Com):
        return
    R_Com_bp = group.identity()
    for item in R_Com[0]:
        R_Com_bp *= item
    
    T_Com_list = [R_Com_bp * S_Com_list[i].pow(-1) for i in range(n)]
    for i in range(n):
        if not poly_commit.verify_eval(T_Com_list[i], i+1, field(0), T_proofs[i]):
            return
    
    return

def _get_dealer_msg(value, t, p, n, poly, poly_commit, poly_commit2, field, group):
    R = poly.random(p, value)
    r = field.random()
    S_list = [None]*n
    for i in range(1,n+1):
        randpoly = poly.random(t, field.rand())
        R_at_i = R(i)
        Si_at_i = randpoly(i)
        randpoly.coeffs[0] = randpoly.coeffs[0] + (R_at_i - Si_at_i)
        S_list[i-1] = randpoly
    R_Com, R_Com_bp =poly_commit2.commit(R, r)
    S_Com_list = [poly_commit.commit(S_i, r) for S_i in S_list]
    
    out_messages = [None]*n
    vector = R_Com[0:2] + [S_Com_list]
    datab = bytearray()
    for item in vector:
        datab.extend(serialize(item))
    C = hashlib.sha256(datab).digest() 
    y_lists = [[S_j(i) for S_j in S_list] for i in range(1,n+1)]
    #can't actually use the double batch create witness here since the batched proofs aren't splitable by the verifier
    S_Com_proofs = [poly_commit.batch_create_witness(S_Com_list[i], S_list[i], n, r) for i in range(n)]
    #switch index order of a doubly-indexed list
    S_Com_proofs = [list(a) for a in zip(*S_Com_proofs)]
    
    T_Com_list = [R_Com_bp * S_Com_list[i].pow(-1) for i in range(n)]
    T_list = [R - S_list[i] for i in range(n)]
    T_proofs = [poly_commit.create_witness(T_Com_list[i], T_list[i], i+1, r * -1) for i in range(n)]
    for i in range(n):
        out_messages[i] = (HavenMessageType.SEND, (C, R_Com, S_Com_list, S_Com_proofs[i], T_proofs, y_lists[i]))
    return out_messages