import asyncio
from pickle import dumps, loads
import secrets
from pypairing import ZR, G1
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1
from adkg.polynomial import polynomials_over
from adkg.broadcast.reliablebroadcast import reliablebroadcast
from adkg.broadcast.optqrbc import optqrbc
from adkg.utils.misc import wrap_send, subscribe_recv

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.DEBUG)

class ACSS_DCR:
    #@profile
    def __init__(
            self, public_keys, private_key, g, n, t, my_id, send, recv, field=ZR
    ):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.my_id = n, t, my_id
        self.g = g

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.field = field
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache()
        self.output_queue = asyncio.Queue()
        self.dual_codes = {}
        # assume the same dual code can be used multiple times safely
        self.dual_codes[(t,n)] = gen_dual_code(n,t,self.poly)
        self.tasks = []
    
    def kill(self):
        # self.benchmark_logger.info("ACSS kill called")
        self.subscribe_recv_task.cancel()
        # self.benchmark_logger.info("ACSS recv task cancelled")
        for task in self.tasks:
            task.cancel()
        # self.benchmark_logger.info("ACSS self.tasks cancelled")

    #@profile
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg):
        comms, encryptions, _ = loads(rbc_msg)
        #Check 1: check each encryption proof is valid
        # for i in range(self.n):
        #     if not verify_knowledge_of_discrete_log(self.public_keys[i], self.g, comms[i], encryptions[i], proofs[i]):
        #         return False
                
        # #Check 2: verify that polynomial is degree d
        # if not self.check_degree(self.t, comms):
        #     return False
        share = ZR(self.private_key.raw_decrypt(encryptions[self.my_id]))
        self.output_queue.put_nowait((dealer_id, avss_id, [int(share)], comms))
    
    def check_degree(self, claimed_degree, commitments):
        if (claimed_degree, len(commitments)) not in self.dual_codes.keys():
            self.dual_codes[(claimed_degree, len(commitments))] = gen_dual_code(len(commitments), claimed_degree, self.poly)
        dual_code = self.dual_codes[(claimed_degree, len(commitments))]

        check = self.g ** 0
        for i in range(len(commitments)):
            check *= commitments[i] ** dual_code[i]
        return check == self.g ** 0

    def _get_dealer_msg(self, secret, n):
        phi = self.poly.random(self.t, secret)
        outputs = [prove_knowledge_of_encrypted_dlog(self.g, phi(i+1), self.public_keys[i]) for i in range(n)]
        return dumps([[outputs[i][j] for i in range(n)] for j in range(3)])

    #@profile
    async def avss(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share secrets."
        # If `secret` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int
        logger.info("pant")

        logger.debug(
            "[%d] Starting AVSS. Id: %s, Dealer Id: %d",
            self.my_id,
            avss_id,
            dealer_id,
        )

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-RBC"
        acsstag = f"{dealer_id}-{avss_id}-AVSS"

        broadcast_msg = None
        if self.my_id == dealer_id:
            # broadcast_msg: phi & public key for reliable broadcast
            # dispersal_msg_list: the list of payload z
            secret = values[0]
            broadcast_msg = self._get_dealer_msg(secret, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            comms, encryptions, proofs = loads(_m)
            #Check 1: verify that polynomial is degree d
            if not self.check_degree(self.t, comms):
                return False
            
            #Check 2: check each encryption proof is valid
            for i in range(self.n):
                if not verify_knowledge_of_discrete_log(self.public_keys[i], self.g, comms[i], encryptions[i], proofs[i]):
                    return False
            return True

        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))  # (# noqa: E501)

        rbc_msg = await output.get()

        # avss processing
        logger.debug("checking dealer msg")
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg)
        #self.subscribe_recv_task.cancel()

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
    