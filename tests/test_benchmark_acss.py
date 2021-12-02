from pytest import mark
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_feldman import PolyCommitFeldman
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.utils.serilization import serialize_g, deserialize_g, serialize_gs, deserialize_gs, deserialize_f
import hashlib
# from pypairing import Curve25519G as group, Curve25519ZR as field
from pypairing import G1 as group, ZR as field

class HavenMessageType:
    ECHO = 1
    READY = 2
    SEND = 3

def get_avss_params(n, t):
    # from pypairing import G1, ZR
    g = group.rand()
    h = group.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = field.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys

@mark.parametrize(
    "t, p, n",
    [
        (2, 2, 7),
        (2, 3, 7),
    ])
def test_benchmark_acss_dealer(benchmark, t, p, n):
    value = field.rand()
    poly = polynomials_over(field)
    g, h, pks, sks = get_avss_params(n, t)
    pc = PolyCommitFeldman(g)
    benchmark(_get_dealer_msg, [value], t, n, poly, pks, pc, g, field)

@mark.parametrize(
    "t, p, n",
    [
        (2, 2, 7),
        (2, 3, 7),
    ])
def test_benchmark_hybrid_haven_receiver(benchmark, t, p, n):
    #from pypairing import G1 as group, ZR as field
    value = field.rand()
    poly = polynomials_over(field)
    g, h, pks, sks = get_avss_params(n, t)
    pc = PolyCommitFeldman(g)
    msgs = _get_dealer_msg([value], t, n, poly, pks, pc, g, field)
    benchmark( _handle_dealer_msg, msgs, t, 0, pc, sks[0])

def decode_proposal(proposal, t, my_id):
    g_size = 48
    c_size = 64

    commit_data = proposal[0:g_size*(t+1)]
    commits = deserialize_gs(commit_data) 

    ephkey_data = proposal[g_size*(t+1):g_size*(t+2)]
    ephkey = deserialize_g(ephkey_data)

    dispersal_msg_raw = proposal[g_size*(t+2):]
    dispersal_msg = dispersal_msg_raw[my_id*c_size : (my_id+1)*c_size]

    return (dispersal_msg, commits, ephkey)

def _handle_dealer_msg(msg, t, my_id, pc, sk):
    dispersal_msg, commits, ephkey = decode_proposal(msg, t, my_id)
    commitments, ephemeral_public_key = [commits], ephkey
    shared_key = pow(ephemeral_public_key, sk)

    try:
        sharesb = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
    except ValueError as e:  # TODO: more specific exception
        return
    
    witnesses = [None]
    shares = [deserialize_f(sharesb)]
    pc.batch_verify_eval(commitments, my_id + 1, shares, witnesses, t)

    return

def _get_dealer_msg(values, t, n, poly, pks, pc, g, field):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        secret_count = len(values)
        phi = [None] * secret_count
        commitments = [None] * secret_count
        # BatchPolyCommit
        #   Cs  <- BatchPolyCommit(SP,φ(·,k))
        # TODO: Whether we should keep track of that or not
        # r = ZR.random()
        r = field.random()
        for k in range(secret_count):
            phi[k] = poly.random(t, values[k])
            commitments[k] = pc.commit(phi[k], r)


        ephemeral_secret_key = field.random()
        ephemeral_public_key = pow(g, ephemeral_secret_key)
        dispersal_msg_list = bytearray()
        witnesses = pc.double_batch_create_witness(commitments, phi, n, r)
        for i in range(n):
            shared_key = pow(pks[i], ephemeral_secret_key)
            phis_i = [phi[k](i + 1).__getstate__() for k in range(secret_count)]
            # z = (phis_i, witnesses[i])
            # zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
            zz = SymmetricCrypto.encrypt(str(shared_key).encode(), phis_i[0])
            dispersal_msg_list.extend(zz)
        commitments[0].append(ephemeral_public_key)
        datab = serialize_gs(commitments[0]) # Serializing commitments
        
        # TODO: Note that this only works for hbACSS
        datab.extend(dispersal_msg_list) # Appending the AVID messages
        return bytes(datab)