import logging
import asyncio
import pypairing
from pickle import dumps, loads
#from honeybadgermpc.betterpairing import ZR, G1
# from pypairing import ZR, G1
from pypairing import Curve25519ZR as ZR, Curve25519G as G1
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.broadcast.reliablebroadcast import reliablebroadcast
from honeybadgermpc.broadcast.avid import AVID
from honeybadgermpc.utils.misc import wrap_send, subscribe_recv
from honeybadgermpc.share_recovery import poly_lagrange_at_x, poly_interpolate_at_x, interpolate_g1_at_x
import time

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)


class HbAVSSMessageType:
    OK = "OK"
    IMPLICATE = "IMPLICATE"
    READY = "READY"
    RECOVERY = "RECOVERY"
    RECOVERY1 = "RECOVERY1"
    RECOVERY2 = "RECOVERY2"
    KDIBROADCAST = "KDIBROADCAST"


def get_avss_params(n, t):
    g, h = G1.rand(), G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random(0)
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


class Hbacss0:
    #@profile
    def __init__(
            self, public_keys, private_key, crs, n, t, my_id, send, recv, pc=None, field=ZR
    ):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.my_id = n, t, my_id
        #todo: g should be baked into the pki or something
        if type(crs[0]) is G1:
            self.g = crs[0]
        else:
            self.g = crs[0][0]

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.field = field
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache()
        if pc is not None:
            self.poly_commit = pc
        else:
            self.poly_commit = PolyCommitLog(crs=None, degree_max=t)
            # self.poly_commit.preprocess_prover()
            # self.poly_commit.preprocess_verifier()
        self.avid_msg_queue = asyncio.Queue()
        self.tasks = []
        self.shares_future = asyncio.Future()
        self.output_queue = asyncio.Queue()
        self.tagvars = {}

    async def _recv_loop(self, q):
        while True:
            avid, tag, dispersal_msg_list = await q.get()
            self.tasks.append(
                asyncio.create_task(avid.disperse(tag, self.my_id, dispersal_msg_list))
            )

    def __enter__(self):
        self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        return self

    def __exit__(self, typ, value, traceback):
        self.subscribe_recv_task.cancel()
        self.avid_recv_task.cancel()
        for task in self.tasks:
            task.cancel()
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
        implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, j)
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
            avid = self.tagvars[tag]['avid']
            retrieved_msg = await avid.retrieve(tag, sender)
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
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self.tagvars[tag] = {}
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['avid'] = avid
        implicate_sent = False
        self.tagvars[tag]['in_share_recovery'] = False
        # get phi and public key from reliable broadcast msg
        #commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)

        # this function will both load information into the local variable store 
        # and verify share correctness
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dispersal_msg, rbc_msg)
        if self.tagvars[tag]['all_shares_valid']:
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
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
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
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
                    self.output_queue.put_nowait((dealer_id, avss_id, int_shares))
                    output = True
                    logger.debug("[%d] Output", self.my_id)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                self.tagvars[tag] = {}
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
        dispersal_msg_list = [None] * n
        witnesses = self.poly_commit.double_batch_create_witness(phi, r)
        for i in range(n):
            shared_key = pow(self.public_keys[i], ephemeral_secret_key)
            phis_i = [phi[k](i + 1) for k in range(secret_count)]
            z = (phis_i, witnesses[i])
            zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
            dispersal_msg_list[i] = zz

        return dumps((commitments, ephemeral_public_key)), dispersal_msg_list
    #@profile
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg):
        all_shares_valid = True
        commitments, ephemeral_public_key = loads(rbc_msg)
        shared_key = pow(ephemeral_public_key, self.private_key)
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commitments
        self.tagvars[tag]['ephemeral_public_key'] = ephemeral_public_key
        
        try:
            shares, witnesses = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False

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
    async def avss(self, avss_id, values=None, dealer_id=None, client_mode=False):
        """
        A batched version of avss with share recovery
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
        if client_mode:
            assert dealer_id is not None
            assert dealer_id == self.n
        assert type(avss_id) is int

        logger.debug(
            "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d, Client Mode: %s",
            self.my_id,
            avss_id,
            dealer_id,
            client_mode,
        )

        # In the client_mode, the dealer is the last node
        n = self.n if not client_mode else self.n + 1
        broadcast_msg = None
        dispersal_msg_list = None
        if self.my_id == dealer_id:
            # broadcast_msg: phi & public key for reliable broadcast
            # dispersal_msg_list: the list of payload z
            broadcast_msg, dispersal_msg_list = self._get_dealer_msg(values, n)

        tag = f"{dealer_id}-{avss_id}-B-RBC"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)
        rbc_msg = await reliablebroadcast(
            tag,
            self.my_id,
            n,
            self.t,
            dealer_id,
            broadcast_msg,
            recv,
            send,
            client_mode=client_mode,
        )  # (# noqa: E501)
        tag = f"{dealer_id}-{avss_id}-B-AVID"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        logger.debug("[%d] Starting AVID disperse", self.my_id)
        avid = AVID(n, self.t, dealer_id, recv, send, n)
        if client_mode and self.my_id == dealer_id:
            # In client_mode, the dealer is not supposed to do
            # anything after sending the initial value.
            await avid.disperse(tag, self.my_id, dispersal_msg_list, client_mode=True)
            self.shares_future.set_result(True)
            return

        # start disperse in the background
        self.avid_msg_queue.put_nowait((avid, tag, dispersal_msg_list))

        # avss processing
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg, avid)


class Hbacss1(Hbacss0):
    def _init_recovery_vars(self, tag):
        self.tagvars[tag]['finished_interpolating_commits'] = False
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        if not self.tagvars[tag]['in_share_recovery']:
            return
        ls = len(self.tagvars[tag]['commitments']) // (self.t + 1)
        send, recv, multicast = self.tagvars[tag]['io']
        if not self.tagvars[tag]['finished_interpolating_commits']:
            all_commits = [ [] for l in range(ls)]
            for l in range(ls):
                known_commits = self.tagvars[tag]['commitments'][l * (self.t + 1): (1 + l) * (self.t + 1)]
                known_commit_coords = [[i + 1, known_commits[i]] for i in range(self.t + 1)]
                # line 502
                interpolated_commits = [interpolate_g1_at_x(known_commit_coords, i + 1) for i in range(self.t + 1, self.n)]
                #interpolated_commits = known_commits + known_commits + known_commits
                all_commits[l] = known_commits + interpolated_commits
            self.tagvars[tag]['all_commits'] = all_commits
            self.tagvars[tag]['finished_interpolating_commits'] = True

            #init some variables we'll need later
            self.tagvars[tag]['r1_coords_l'] = [ [] for l in range(ls)]
            self.tagvars[tag]['r2_coords_l'] = [ [] for l in range(ls)]
            self.tagvars[tag]['sent_r2'] = False
            self.tagvars[tag]['r1_set'] = set()
            self.tagvars[tag]['r2_set'] = set()
            
            if self.tagvars[tag]['all_shares_valid']:
                logger.debug("[%d] prev sent r1", self.my_id)
                all_evalproofs = [ [] for l in range(ls)]
                all_points = [ [] for l in range(ls)]
                for l in range(ls):
                    # the proofs for the specific shares held by this node
                    known_evalproofs = self.tagvars[tag]['witnesses'][l * (self.t + 1): (1 + l) * (self.t + 1)]
                    known_evalproof_coords = [[i + 1, known_evalproofs[i]] for i in range(self.t + 1)]
                    # line 504
                    interpolated_evalproofs = [interpolate_g1_at_x(known_evalproof_coords, i + 1) for i in
                                            range(self.t + 1, self.n)]
                    #interpolated_evalproofs = known_evalproofs + known_evalproofs + known_evalproofs
                    all_evalproofs[l] = known_evalproofs + interpolated_evalproofs
    
                    # another way of doing the bivariate polynomial. Essentially the same as how commits are interpolated
                    known_points = self.tagvars[tag]['shares'][l * (self.t + 1): (1 + l) * (self.t + 1)]
                    known_point_coords = [[i + 1, known_points[i]] for i in range(self.t + 1)]
                    mypoly = self.poly.interpolate(known_point_coords)
                    interpolated_points = [mypoly(i+1) for i in range(self.t + 1, self.n)]
                    all_points[l] = known_points + interpolated_points
                logger.debug("[%d] in between r1", self.my_id)
                # lines 505-506
                for j in range(self.n):
                    send(j, (HbAVSSMessageType.RECOVERY1, [ all_points[l][j] for l in range(ls)] , [all_evalproofs[l][j] for l in range(ls)]))
                logger.debug("[%d] sent r1", self.my_id)

        if avss_msg[0] == HbAVSSMessageType.RECOVERY1 and not self.tagvars[tag]['sent_r2']:
            logger.debug("[%d] prev sent r2", self.my_id)
            _, points, proofs = avss_msg
            all_commits = self.tagvars[tag]['all_commits']
            if self.poly_commit.batch_verify_eval([all_commits[l][self.my_id] for l in range(ls)], sender + 1, points, proofs):
                if sender not in self.tagvars[tag]['r1_set']:
                    self.tagvars[tag]['r1_set'].add(sender)
                    for l in range(ls):
                        self.tagvars[tag]['r1_coords_l'][l].append([sender, points[l]])
                    #r1_coords.append([sender, point])
                if len(self.tagvars[tag]['r1_set']) == self.t + 1:
                    #r1_poly = self.poly.interpolate(r1_coords)
                    r1_poly_l = [ [] for l in range(ls)]
                    for l in range(ls):
                        r1_poly_l[l] = self.poly.interpolate(self.tagvars[tag]['r1_coords_l'][l])
                    for j in range(self.n):
                        r1_points_j = [r1_poly_l[l](j) for l in range(ls)]
                        #send(j, (HbAVSSMessageType.RECOVERY2, r1_poly(j)))
                        send(j, (HbAVSSMessageType.RECOVERY2, r1_points_j))
                    self.tagvars[tag]['sent_r2'] = True
                    logger.debug("[%d] sent r2", self.my_id)

        if avss_msg[0] == HbAVSSMessageType.RECOVERY2 and not self.tagvars[tag]['all_shares_valid']: # and self.tagvars[tag]['sent_r2']:
            _, points = avss_msg
            if sender not in self.tagvars[tag]['r2_set']:
                self.tagvars[tag]['r2_set'].add(sender)
                #r2_coords.append([sender, point])
                for l in range(ls):
                    self.tagvars[tag]['r2_coords_l'][l].append([sender, points[l]])
            if len(self.tagvars[tag]['r2_set']) == 2 * self.t + 1:
                # todo, replace with robust interpolate that takes at least 2t+1 values
                # this will still interpolate the correct degree t polynomial if all points are correct
                r2_poly_l = [ [] for l in range(ls)]
                shares = []
                for l in range(ls):
                    r2_poly = self.poly.interpolate(self.tagvars[tag]['r2_coords_l'][l])
                    shares += [r2_poly(i) for i in range(self.t + 1)]
                multicast((HbAVSSMessageType.OK, ""))
                self.tagvars[tag]['all_shares_valid'] = True
                self.tagvars[tag]['shares'] = shares


class Hbacss2(Hbacss0):
    #@profile
    async def _handle_implication(self, tag, j, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        orig_poly_commitments = self.tagvars[tag]['orig_poly_commitments']
        redundant_poly_commitments = self.tagvars[tag]['redundant_poly_commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            return False
        # decrypt and verify
        implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, j)
        j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)
        secret_count = len(orig_poly_commitments)
        try:
            (j_orig_shares, j_orig_poly_witnesses,
             j_redundant_poly_witnesses) = SymmetricCrypto.decrypt(
                str(j_shared_key).encode(), implicate_msg
            )
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        j_redundant_shares = []
        # Interpolate to get redundant_shares
        # todo:we can interpolate only if needed, but this captures the worst case for benchmarks
        for batch_idx in range(secret_count // (self.t + 1)):
            base_idx = batch_idx * (self.t + 1)
            known_coords = [[i + 1, j_orig_shares[base_idx + i]] for i in range(self.t + 1)]
            j_poly = self.poly.interpolate(known_coords)
            j_redundant_shares += [j_poly(i + 1) for i in range(self.t + 1, self.n)]

        FLAG_verify_correct = True
        for i in range(len(j_orig_poly_witnesses)):
            FLAG_verify_correct &= self.poly_commit.batch_verify_eval(
                orig_poly_commitments[i::(self.t + 1)], j + 1, j_orig_shares[i::(self.t + 1)], j_orig_poly_witnesses[i])
            if not FLAG_verify_correct:
                break
        if FLAG_verify_correct:
            for i in range(len(j_redundant_poly_witnesses)):
                FLAG_verify_correct &= self.poly_commit.batch_verify_eval(
                    redundant_poly_commitments[i::(self.n - (self.t + 1))], j + 1,
                    j_redundant_shares[i::(self.n - (self.t + 1))],
                    j_redundant_poly_witnesses[i]
                )
                if not FLAG_verify_correct:
                    break
        return not FLAG_verify_correct
    #@profile
    def _get_dealer_msg(self, values, n):
        # Notice we currently required the number of values shared to be divisible by t+1.
        logger.debug("[%d] Start generating msg", self.my_id)
        secret_count = len(values)
        redundant_poly_count = secret_count // (self.t + 1) * (n - (self.t + 1))
        r = ZR.random()
        phis = [self.poly.random(self.t, values[k]) for k in range(secret_count)]
        psis = []
        orig_poly_commitments = [self.poly_commit.commit(phis[k], r) for k in range(secret_count)]
        for batch_idx in range(secret_count // (self.t + 1)):
            base_idx = batch_idx * (self.t + 1)
            known_polys = [[i + 1, phis[base_idx + i]] for i in range(self.t + 1)]
            psis.extend([poly_interpolate_at_x(self.poly, known_polys, i + 1) for
                         i in
                         range(self.t + 1, self.n)])
        redundant_poly_commitments = [self.poly_commit.commit(psis[k], r) for k in range(redundant_poly_count)]

        ephemeral_secret_key = self.field.random()
        ephemeral_public_key = pow(self.g, ephemeral_secret_key)
        dispersal_msg_list = [None] * n
        orig_poly_witnesses = [self.poly_commit.double_batch_create_witness(phis[i::(self.t + 1)], r) for i in
                               range(self.t + 1)]
        redundant_poly_witnesses = [self.poly_commit.double_batch_create_witness(psis[i::(n - (self.t + 1))], r) for i
                                    in
                                    range(n - (self.t + 1))]
        for i in range(n):
            shared_key = pow(self.public_keys[i], ephemeral_secret_key)
            orig_shares = [phis[k](i + 1) for k in range(secret_count)]
            # redundant_shares = [psis[k](i + 1) for k in range(redundant_poly_count)]
            # Redundant shares are not required to send.
            z = (orig_shares, [orig_poly_witnesses[j][i] for j in range(self.t + 1)],
                 [redundant_poly_witnesses[j][i] for j in range(n - (self.t + 1))])
            zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
            dispersal_msg_list[i] = zz

        return dumps((orig_poly_commitments, redundant_poly_commitments, ephemeral_public_key)), dispersal_msg_list
    #@profile
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg):
        all_shares_valid = True
        orig_poly_commitments, redundant_poly_commitments, ephemeral_public_key = loads(rbc_msg)
        shared_key = pow(ephemeral_public_key, self.private_key)
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['orig_poly_commitments'] = orig_poly_commitments
        self.tagvars[tag]['redundant_poly_commitments'] = redundant_poly_commitments
        self.tagvars[tag]['ephemeral_public_key'] = ephemeral_public_key
        secret_count = len(orig_poly_commitments)
        orig_shares = []
        orig_poly_witnesses = []
        redundant_poly_witnesses = []
        try:
            (orig_shares, orig_poly_witnesses,
             redundant_poly_witnesses) = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            return False

        redundant_shares = []
        # Interpolate to get redundant_shares
        for batch_idx in range(secret_count // (self.t + 1)):
            base_idx = batch_idx * (self.t + 1)
            known_coords = [[i + 1, orig_shares[base_idx + i]] for i in range(self.t + 1)]
            temp_interpolated_poly = self.poly.interpolate(known_coords)
            redundant_shares += [temp_interpolated_poly(i + 1) for i in
                                 range(self.t + 1, self.n)]

        total_witnesses = orig_poly_witnesses + redundant_poly_witnesses
        total_shares = []
        total_commitments = []
        for batch_idx in range(secret_count // (self.t + 1)):
            base_orig_idx = batch_idx * (self.t + 1)
            base_redundant_idx = batch_idx * (self.n - self.t - 1)
            total_shares += orig_shares[base_orig_idx:(base_orig_idx + self.t + 1)]
            total_shares += redundant_shares[base_redundant_idx:(base_redundant_idx + self.n - (self.t + 1))]
            total_commitments += orig_poly_commitments[base_orig_idx:(base_orig_idx + self.t + 1)]
            total_commitments += redundant_poly_commitments[
                                 base_redundant_idx:(base_redundant_idx + self.n - (self.t + 1))]
        self.tagvars[tag]['total_commitments'] = total_commitments
        self.tagvars[tag]['total_shares'] = total_shares
        self.tagvars[tag]['total_witnesses'] = total_witnesses
        # call if decryption was successful
        for i in range(len(orig_poly_witnesses)):
            all_shares_valid &= self.poly_commit.batch_verify_eval(
                orig_poly_commitments[i::(self.t + 1)], self.my_id + 1, orig_shares[i::(self.t + 1)],
                orig_poly_witnesses[i])
            if not all_shares_valid:
                break
        if all_shares_valid:
            for i in range(len(redundant_poly_witnesses)):
                all_shares_valid &= self.poly_commit.batch_verify_eval(
                    redundant_poly_commitments[i::(self.n - (self.t + 1))], self.my_id + 1,
                    redundant_shares[i::(self.n - (self.t + 1))],
                    redundant_poly_witnesses[i]
                )
                if not all_shares_valid:
                    break
        if all_shares_valid:
            self.tagvars[tag]['shares'] = orig_shares
            self.tagvars[tag]['orig_poly_witnesses'] = orig_poly_witnesses
            self.tagvars[tag]['redundant_poly_witnesses'] = redundant_poly_witnesses
            
        return all_shares_valid

    def _init_recovery_vars(self, tag):
        self.tagvars[tag]['r1_sent'] = False
        self.tagvars[tag]['passed_r1'] = False
        self.tagvars[tag]['r1_set'] = set()
        self.tagvars[tag]['r2_set'] = set()
        self.tagvars[tag]['r1_value_ls'] = []
        self.tagvars[tag]['r2_value_ls'] = []
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        if not self.tagvars[tag]['in_share_recovery']:
            return
        send, recv, multicast = self.tagvars[tag]['io']
        if self.tagvars[tag]['all_shares_valid'] and not self.tagvars[tag]['r1_sent']:
            logger.debug("[%d] in share_recovery and all_shares_valid", self.my_id)
            total_shares = self.tagvars[tag]['total_shares']
            total_witnesses = self.tagvars[tag]['total_witnesses']
            for j in range(self.n):
                msg = (HbAVSSMessageType.RECOVERY1, (total_shares[j::self.n], total_witnesses[j]))
                send(j, msg)
            self.tagvars[tag]['r1_sent'] = True
            logger.debug("[%d] after share_recovery and all_shares_valid", self.my_id)
        if avss_msg[0] == HbAVSSMessageType.RECOVERY1 and not self.tagvars[tag]['passed_r1']:
            logger.debug("[%d] start r1", self.my_id)
            total_commitments = self.tagvars[tag]['total_commitments']
            (on_receive_shares, on_receive_witnesses) = avss_msg[1]
            if self.poly_commit.batch_verify_eval(
                    total_commitments[self.my_id::self.n], sender + 1,
                    on_receive_shares,
                    on_receive_witnesses
            ):
                self.tagvars[tag]['r1_set'].add(sender)
                self.tagvars[tag]['r1_value_ls'].append([sender, on_receive_shares, on_receive_witnesses])
            if len(self.tagvars[tag]['r1_set']) == (self.t + 1):
                # Interpolate
                interpolated_polys = []
                for poly_idx in range(len(self.tagvars[tag]['r1_value_ls'][0][1])):
                    known_point_coords = [[self.tagvars[tag]['r1_value_ls'][i][0] + 1, self.tagvars[tag]['r1_value_ls'][i][1][poly_idx]] for i in
                                          range(self.t + 1)]
                    interpolated_polys.append(self.poly.interpolate(known_point_coords))
                # Send
                for j in range(self.n):
                    msg = (
                        HbAVSSMessageType.RECOVERY2,
                        [interpolated_polys[i](j + 1) for i in range(len(interpolated_polys))])
                    send(j, msg)
                self.tagvars[tag]['passed_r1'] = True
            logger.debug("[%d] after r1", self.my_id)
        if avss_msg[0] == HbAVSSMessageType.RECOVERY2 and self.tagvars[tag]['passed_r1'] and not self.tagvars[tag]['all_shares_valid']:#(not ok_sent) and (not passed_r2):
            logger.debug("[%d] start r2 handling", self.my_id)
            if sender not in self.tagvars[tag]['r2_set']:
                self.tagvars[tag]['r2_set'].add(sender)
                _, on_receive_shares = avss_msg
                self.tagvars[tag]['r2_value_ls'].append([sender, on_receive_shares])
            if len(self.tagvars[tag]['r2_set']) == 2 * self.t + 1:
                # todo, replace with robust interpolate that takes at least 2t+1 values
                # this will still interpolate the correct degree t polynomial if all points are correct
                orig_shares = []
                for i in range(len(self.tagvars[tag]['r2_value_ls'][0][1])):
                    coords = [[self.tagvars[tag]['r2_value_ls'][j][0] + 1, self.tagvars[tag]['r2_value_ls'][j][1][i]] for j in range(len(self.tagvars[tag]['r2_value_ls']))]
                    r2_poly = self.poly.interpolate(coords)
                    orig_shares += [r2_poly(j + 1) for j in range(self.t + 1)]
                self.tagvars[tag]['all_shares_valid'] = True
                multicast((HbAVSSMessageType.OK, ""))
                self.tagvars[tag]['shares'] = orig_shares
            logger.debug("[%d] after r2 handling", self.my_id)
