import asyncio
from hashlib import sha256
from pickle import dumps, loads
#from pypairing import ZR, G1
from pypairing import Curve25519ZR as ZR, Curve25519G as G1
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.utils.misc import wrap_send, subscribe_recv
from honeybadgermpc.proofs import MerkleTree
import time
import hashlib
from honeybadgermpc.utils.serilization import serialize_gs, deserialize_gs

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
logger.setLevel(logging.INFO)


class HavenMessageType:
    ECHO = 1
    READY = 2
    SEND = 3

class HavenAVSS:

    def __init__(self, n, t, p, my_id, send, recv, pc, field=ZR):
        self.n, self.t, self.p, self.my_id = n, t, p, my_id
        self.poly_commit = pc

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
        self.tasks = []
        self.commitments = {}
        self.shares = {}

    def kill(self):
        self.subscribe_recv_task.cancel()
        for task in self.tasks:
            task.cancel()

    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id):
        tag = f"{dealer_id}-{avss_id}"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        echo_sets = {}
        ready_sets = {}
        echo_coords = {}
        ready_sent = False
        dealer_msg_handled = False
        waiting_for_echoes = False #line 29
        consensus_C = None

        while True:
            sender, avss_msg  = await recv()
            if avss_msg[0] == HavenMessageType.SEND and not dealer_msg_handled:
                self._handle_dealer_msg(tag, avss_msg[1], send)
                dealer_msg_handled = True

            elif avss_msg[0] == HavenMessageType.ECHO:
                try:
                    C, S_Com_i, S_Com_proofs_i, y_list_j_i = avss_msg[1]
                except Exception:
                    continue

                # TODO: to optimize here, if the node alreay has the required data, it can skip the next two verification!
                #--  if not MerkleTree.verify_membership(dumps(S_Com_i), branch, C):
                #--     continue
                    
                #-- if not self.poly_commit.verify_eval(S_Com_i, sender+1, y_list_j_i, S_Com_proofs_i):
                #--    continue

                if C not in echo_sets:
                    echo_sets[C] = set()
                    echo_coords[C] = []
                echo_sets[C].add(sender)
                echo_coords[C].append((sender+1, y_list_j_i))
                if len(echo_sets[C]) == 2 * self.t + 1 and not ready_sent:
                    multicast((HavenMessageType.READY, C))
                    ready_sent = True
                if waiting_for_echoes and C == consensus_C and len(echo_sets[C]) == self.t + 1:
                    self.output_queue.put_nowait((dealer_id, avss_id, [self.shares[C]], self.commitments[C]))
                    break

            elif avss_msg[0] == HavenMessageType.READY:
                try:
                    C = avss_msg[1]
                except Exception:
                    continue

                if C not in ready_sets:
                    ready_sets[C] = set()
                ready_sets[C].add(sender)
                if len(ready_sets[C]) == self.t + 1 and not ready_sent:
                    multicast((HavenMessageType.READY, C))
                    ready_sent = True
                if len(ready_sets[C]) == 2 * self.t + 1 and not waiting_for_echoes:
                    if len(echo_sets[C]) < self.t + 1:
                        waiting_for_echoes = True
                        consensus_C = C
                    else:
                        self.output_queue.put_nowait((dealer_id, avss_id, [self.shares[C]], self.commitments[C]))
                        logger.info(f"Outputting share at {time.time()-self.start_time}")
                        break

    #@profile
    def _handle_dealer_msg(self, tag, dealer_msg, send):
        try:
            (C, R_Com, S_Com_list, S_Com_proofs_i, T_i_proof, y_list_i, y_t) = dealer_msg
        except Exception:
            return
        
        #since you need to check the location of every item in the merkle tree, just rebuild the tree...
        vector = [R_Com] + S_Com_list
        bytes_vector = [dumps(item) for item in vector]
        vCom = MerkleTree(bytes_vector)
        C_reconstructed = vCom.get_root_hash()
        if not C == C_reconstructed:
            return
        
        #if not self.poly_commit.batch_verify_eval(S_Com_list, self.my_id+1, y_list_i, S_Com_proofs_i, self.t):
        for j in range(self.n):
            if not self.poly_commit.verify_eval(S_Com_list[j], self.my_id+1, y_list_i[j], S_Com_proofs_i[j]):
                return
        T_Com_i = self.poly_commit.commit_sub(R_Com, S_Com_list[self.my_id])
        if not self.poly_commit.verify_eval(T_Com_i, self.my_id+1, self.field(0), T_i_proof):
            return
        
        for j in range(self.n):
            send(j, (HavenMessageType.ECHO, (C, S_Com_list[j], S_Com_proofs_i[j], y_list_i[j], vCom.get_branch(j+1))))
        return

    def _get_dealer_msg(self, value, n):
        R = self.poly.random(self.p, value)
        r = self.field.random()
        S_list = [None] * n
        for i in range(1,n+1):
            randpoly = self.poly.random(self.t, self.field.rand())
            R_at_i = R(i)
            Si_at_i = randpoly(i)
            # set S_i(i) := R(i)
            randpoly.coeffs[0] = randpoly.coeffs[0] + (R_at_i - Si_at_i)
            S_list[i-1] = randpoly
        R_Com = self.poly_commit.commit(R, r)
        S_Com_list = [self.poly_commit.commit(S_i, r) for S_i in S_list]
        
        out_messages = [None] * n
        vector = [R_Com] + S_Com_list
        bytes_vector = [dumps(item) for item in vector]
        vCom = MerkleTree(bytes_vector)
        C = vCom.get_root_hash()
        #all_branches = [vCom.get_branch(i) for i in range(n+1)]
        y_t = [self.field(0) for i in range(n)]
        y_lists = [[S_j(i) for S_j in S_list] for i in range(1,n+1)]
        #can't actually use the double batch create witness here since the batched proofs aren't splitable by the verifier
        #S_Com_proofs = self.poly_commit.double_batch_create_witness(S_Com_list, S_list, n)
        S_Com_proofs = [self.poly_commit.batch_create_witness(S_Com_list[i], S_list[i], n, r) for i in range(n)]
        #switch index order of a doubly-indexed list
        S_Com_proofs = [list(a) for a in zip(*S_Com_proofs)]
        
        for i in range(1,n+1):
            T_Com_i = self.poly_commit.commit_sub(R_Com, S_Com_list[i-1])
            T_i = R - S_list[i-1]
            T_i_proof = self.poly_commit.create_witness(T_Com_i, T_i, i, r)
            #packing things into a tuple is the easiest way to handle serializing random objects
            #out_messages[i-1] = (HavenMessageType.SEND, dumps((C, R_Com, S_Com_list, y_list_i, y_t, all_branches)))
            out_messages[i-1] = (HavenMessageType.SEND, (C, R_Com, S_Com_list, S_Com_proofs[i-1], T_i_proof, y_lists[i-1], y_t))
        return out_messages

    #@profile
    async def avss(self, avss_id, value=None, dealer_id=None):
        if value is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        if self.my_id == dealer_id:
            msg_list = self._get_dealer_msg(value, self.n)
            tag = f"{dealer_id}-{avss_id}"
            send = self.get_send(tag)
            for i in range(self.n):
                send(i, msg_list[i])

        # avss processing
        logger.debug("starting acss")
        await self._process_avss_msg(avss_id, dealer_id)

class HybridHavenAVSS(HavenAVSS):

    #pc is the commit used for S_i, pc2 is used for R
    def __init__(self, n, t, p, my_id, send, recv, pc, pc2, field=ZR):
        self.poly_commit2 = pc2
        HavenAVSS.__init__(self, n, t, p, my_id, send, recv, pc, field=field)

    def _handle_dealer_msg(self, tag, dealer_msg, send):
        try:
            (C, R_Com, S_Com_list, S_Com_proofs_i, T_i_proof, y_list_i) = dealer_msg
        except Exception:
            return
        
        # TODO:
        # 1. Precomute serialization of parameters, hash them and use the hash in the proofs
        vector = R_Com[0:2] + [S_Com_list]
        datab = bytearray()
        for item in vector:
            datab.extend(serialize_gs(item))
        C_local = hashlib.sha256(datab).digest() 
        if not C_local == C:
            return
        
        # TODO: Can we do batch validation here? One idea is: take integer linear combination of all the polynomials.
        #if not self.poly_commit.batch_verify_eval(S_Com_list, self.my_id+1, y_list_i, S_Com_proofs_i, self.t):
        for j in range(self.n):
            if not self.poly_commit.verify_eval(S_Com_list[j], self.my_id+1, y_list_i[j], S_Com_proofs_i[j]):
                return
        
        if not self.poly_commit2.verify_commit(R_Com):
            return
        R_Com_bp = G1.identity()
        # FIXME: how to handle the blind?
        for item in R_Com[0]:
            R_Com_bp *= item
        
        # TODO: Can we ask the dealer for T_Com_i and check whether S*T=R or not? This will save us from taking inverse
        # TODO: I think each node needs to validate T_Com_i for all nodes. Can we do batching here?
        # TODO: To check for each index except yours. I am not sure whether this step can be done in O(n^2) step or not
        T_Com_i = R_Com_bp / S_Com_list[self.my_id]
        if not self.poly_commit.verify_eval(T_Com_i, self.my_id+1, self.field(0), T_i_proof):
            return
        
        self.commitments[C] = R_Com[1] # Feldmann commitment
        self.shares[C] = y_list_i[self.my_id]
        # TODO: Verify Feldman commitment of the share

        for j in range(self.n):
            send(j, (HavenMessageType.ECHO, (C, S_Com_list[j], S_Com_proofs_i[j], y_list_i[j])))
        return

    def _get_dealer_msg(self, value, n):
        R = self.poly.random(self.p, value)
        r = self.field.random()
        S_list = [None]*n
        for i in range(1,n+1):
            randpoly = self.poly.random(self.t, self.field.rand())
            R_at_i = R(i)
            Si_at_i = randpoly(i)
            randpoly.coeffs[0] = randpoly.coeffs[0] + (R_at_i - Si_at_i)
            S_list[i-1] = randpoly
        R_Com, R_Com_bp = self.poly_commit2.commit(R, r)
        S_Com_list = [self.poly_commit.commit(S_i, r) for S_i in S_list]
        
        out_messages = [None]*n
        vector = R_Com[0:2] + [S_Com_list]
        datab = bytearray()
        for item in vector:
            datab.extend(serialize_gs(item))
        C = hashlib.sha256(datab).digest() 
        y_lists = [[S_j(i) for S_j in S_list] for i in range(1,n+1)]
        #can't actually use the double batch create witness here since the batched proofs aren't splitable by the verifier
        #S_Com_proofs = self.poly_commit.double_batch_create_witness(S_Com_list, S_list, n)
        S_Com_proofs = [self.poly_commit.batch_create_witness(S_Com_list[i], S_list[i], n, r) for i in range(n)]
        #switch index order of a doubly-indexed list
        S_Com_proofs = [list(a) for a in zip(*S_Com_proofs)]
        
        for i in range(n):
            # TODO: To check if there is any other way to compute T_Com_i more efficiently
            T_Com_i = R_Com_bp / S_Com_list[i]
            T_i = R - S_list[i]
            #S_Com has an h**r component. Need to flip to -r since it's in the denominator
            T_i_proof = self.poly_commit.create_witness(T_Com_i, T_i, i+1, r * -1)
            out_messages[i] = (HavenMessageType.SEND, (C, R_Com, S_Com_list, S_Com_proofs[i], T_i_proof, y_lists[i]))
        return out_messages
