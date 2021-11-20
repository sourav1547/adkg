import asyncio
from pickle import dumps, loads
from honeybadgermpc.broadcast.crypto.boldyreva import dealer, serialize
# from pypairing import ZR, G1
from pypairing import Curve25519ZR as ZR
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.broadcast.reliablebroadcast import reliablebroadcast
# from honeybadgermpc.broadcast.avid import AVID
from honeybadgermpc.utils.misc import wrap_send, subscribe_recv
from honeybadgermpc.broadcast.qrbc import qrbc
from honeybadgermpc.utils.serilization import serialize_gs, deserialize_gs, deserialize_g

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.DEBUG)


class HbAVSSMessageType:
    OK = 1
    IMPLICATE = 2
    READY = 3
    RECOVERY = 4
    RECOVERY1 = 5
    RECOVERY2 = 6
    KDIBROADCAST = 7

class Hbacss0SingleShare:
    #@profile
    def __init__(
            self, public_keys, private_key, g, n, t, my_id, send, recv, pc, field=ZR
    ):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.my_id = n, t, my_id
        self.g = g
        self.poly_commit = pc

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

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
        self.tagvars = {}
        self.tasks = []

    def __enter__(self):
        return self

    #def __exit__(self, typ, value, traceback):
    def kill(self):
        # self.benchmark_logger.info("ACSS kill called")
        self.subscribe_recv_task.cancel()
        # self.benchmark_logger.info("ACSS recv task cancelled")
        for task in self.tasks:
            task.cancel()
        # self.benchmark_logger.info("ACSS self.tasks cancelled")
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
        # self.benchmark_logger.info("ACSS self tagvars canceled")

    
    #@profile
    async def _handle_implication(self, tag, j, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        commitments =  self.tagvars[tag]['commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            return False
        # decrypt and verify
        # implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, j)
        implicate_msg = None #FIXME: IMPORTANT!!
        j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)

        # Same as the batch size
        secret_count = len(commitments)

        try:
            j_shares, j_witnesses = SymmetricCrypto.decrypt(
                str(j_shared_key).encode(), implicate_msg
            )
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        return not self.poly_commit.batch_verify_eval(
            commitments, j + 1, j_shares, j_witnesses
        )

    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False

    # this function should eventually multicast OK, set self.tagvars[tag]['all_shares_valid'] to True, and set self.tagvars[tag]['shares']
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        send, recv, multicast = self.tagvars[tag]['io']
        if not self.tagvars[tag]['in_share_recovery']:
            return
        if self.tagvars[tag]['all_shares_valid'] and not self.kdi_broadcast_sent:
            logger.debug("[%d] sent_kdi_broadcast", self.my_id)
            kdi = self.tagvars[tag]['shared_key']
            multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
            self.kdi_broadcast_sent = True
        if self.tagvars[tag]['all_shares_valid']:
            return

        if avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
            logger.debug("[%d] received_kdi_broadcast from sender %d", self.my_id, sender)
            
            # FIXME: IMPORTANT!! read the message from rbc output
            # retrieved_msg = await avid.retrieve(tag, sender)
            retrieved_msg = None
            try:
                j_shares, j_witnesses = SymmetricCrypto.decrypt(
                    str(avss_msg[1]).encode(), retrieved_msg
                )
            except Exception as e:  # TODO: Add specific exception
                logger.debug("Implicate confirmed, bad encryption:", e)
            commitments = self.tagvars[tag]['commitments']
            if (self.poly_commit.batch_verify_eval(commitments,
                                                   sender + 1, j_shares, j_witnesses)):
                if not self.saved_shares[sender]:
                    self.saved_shared_actual_length += 1
                    self.saved_shares[sender] = j_shares

        # if t+1 in the saved_set, interpolate and sell all OK
        if self.saved_shared_actual_length >= self.t + 1 and not self.interpolated:
            logger.debug("[%d] interpolating", self.my_id)
            # Batch size
            shares = []
            secret_count = len(self.tagvars[tag]['commitments'])
            for i in range(secret_count):
                phi_coords = [
                    (j + 1, self.saved_shares[j][i]) for j in range(self.n) if self.saved_shares[j] is not None
                ]
                shares.append(self.poly.interpolate_at(phi_coords, self.my_id + 1))
            self.tagvars[tag]['all_shares_valid'] = True
            self.tagvars[tag]['shares'] = shares
            self.tagvars[tag]['in_share_recovery'] = False
            self.interpolated = True
            multicast((HbAVSSMessageType.OK, ""))
    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        # self.tagvars[tag]['avid'] = avid
        implicate_sent = False
        self.tagvars[tag]['in_share_recovery'] = False
        
        # get phi and public key from reliable broadcast msg       
        commit_data = rbc_msg[0:32*(self.t+1)]
        commits = deserialize_gs(commit_data) # commitments

        ephkey_data = rbc_msg[32*(self.t+1):32*(self.t+2)]
        ephkey = deserialize_g(ephkey_data) # ephemeral public key

        # AVID messages
        # TODO: Put this into a function
        dispersal_msg_raw = rbc_msg[32*(self.t+2):]
        dlen = len(dispersal_msg_raw)//self.n
        dispersal_msg = dispersal_msg_raw[self.my_id*dlen : (self.my_id+1)*dlen]
        
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dispersal_msg, ([commits], ephkey))
        if self.tagvars[tag]['all_shares_valid']:
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        ok_set = set()
        ready_set = set()
        implicate_set = set()
        output = False
        ready_sent = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)
                if len(ok_set) >= (2 * self.t + 1) and not ready_sent:
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # READY
            if avss_msg[0] == HbAVSSMessageType.READY and (sender not in ready_set):
                # logger.debug("[%d] Received READY from [%d]", self.my_id, sender)
                ready_set.add(sender)
                if len(ready_set) >= (self.t + 1) and not ready_sent:
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # if 2t+1 ready -> output shares
            if len(ready_set) >= (2 * self.t + 1):
                # output result by setting the future value
                if self.tagvars[tag]['all_shares_valid'] and not output:
                    shares = self.tagvars[tag]['shares']
                    int_shares = [int(shares[i]) for i in range(len(shares))]
                    commitments = self.tagvars[tag]['commitments']
                    self.output_queue.put_nowait((dealer_id, avss_id, int_shares, commitments))
                    output = True
                    logger.debug("[%d] Output", self.my_id)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    #@profile
    def _get_dealer_msg(self, values, n):
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
        r = ZR.random()
        for k in range(secret_count):
            phi[k] = self.poly.random(self.t, values[k])
            commitments[k] = self.poly_commit.commit(phi[k], r)


        ephemeral_secret_key = self.field.random()
        ephemeral_public_key = pow(self.g, ephemeral_secret_key)
        dispersal_msg_list = bytearray()
        witnesses = self.poly_commit.double_batch_create_witness(phi, r, self.n)
        for i in range(n):
            shared_key = pow(self.public_keys[i], ephemeral_secret_key)
            phis_i = [phi[k](i + 1).__getstate__() for k in range(secret_count)]
            z = (phis_i, witnesses[i])
            zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
            dispersal_msg_list.extend(zz)
        commitments[0].append(ephemeral_public_key)
        datab = serialize_gs(commitments[0]) # Serializing commitments
        
        # TODO: Note that this only works for hbACSS
        datab.extend(dispersal_msg_list) # Appending the AVID messages
        return bytes(datab)
    
    #@profile
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg):
        all_shares_valid = True
        commitments, ephemeral_public_key = rbc_msg
        shared_key = pow(ephemeral_public_key, self.private_key)
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commitments
        self.tagvars[tag]['ephemeral_public_key'] = ephemeral_public_key
        
        try:
            sharesb, witnesses = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
        
        # Note that this only works for a share
        # FIXME: Do this appropriately
        share = ZR()
        share.__setstate__(sharesb[0])
        shares = [share]
        # call if decryption was successful
        if all_shares_valid:
            if self.poly_commit.batch_verify_eval(
                    commitments, self.my_id + 1, shares, witnesses
            ):
                self.tagvars[tag]['shares'] = shares
                self.tagvars[tag]['witnesses'] = witnesses
            else:
                all_shares_valid = False
        return all_shares_valid
    #@profile
    async def avss(self, avss_id, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        # logger.debug(
        #     "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d",
        #     self.my_id,
        #     avss_id,
        #     dealer_id,
        # )

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        if self.my_id == dealer_id:
            # broadcast_msg: phi & public key for reliable broadcast
            broadcast_msg = self._get_dealer_msg(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            return True
        rbc_msg = await qrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            send,
            recv,
        )

        # avss processing
        # logger.debug("starting acss")
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg)
        
        #acss is done, cancel ongoing tasks
        #self.subscribe_recv_task.cancel()
        #self.tagvars[acsstag]['avid_recv_task'].cancel()
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]