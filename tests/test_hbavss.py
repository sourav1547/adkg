from pytest import mark
from random import randint
from contextlib import ExitStack
from pickle import dumps
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_const_dl import PolyCommitConstDL, gen_pc_const_dl_crs
# from honeybadgermpc.betterpairing import G1, ZR
from honeybadgermpc.hbavss import Hbacss0, Hbacss1, Hbacss2
from honeybadgermpc.mpc import TaskProgramRunner
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.utils.misc import print_exception_callback
from honeybadgermpc.field import GF
from honeybadgermpc.elliptic_curve import Subgroup
import asyncio


def get_avss_params(n, t):
    from honeybadgermpc.betterpairing import G1, ZR
    g, h = G1.rand(), G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


def get_avss_params_pyp(n, t):
    from pypairing import G1, ZR
    g, h = G1.rand(), G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


@mark.asyncio
async def test_hbacss0(test_router):
    from pypairing import G1, ZR
    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    sends, recvs, _ = test_router(n)
    # TODO: add configurable crs specifically for poly_commit_log
    crs = [g]

    values = [ZR.random()] * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    shares = [None] * n
    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss0(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )

    assert recovered_values == values

@mark.asyncio
async def test_hbacss0_share_fault(test_router):
    from pypairing import G1, ZR
    # Injects one invalid share
    class BadDealer(Hbacss0):
        def _get_dealer_msg(self, values, n):
            # Sample B random degree-(t) polynomials of form φ(·)
            # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
            # The same as B (batch_size)
            fault_n = randint(1, n - 1)
            fault_k = randint(1, len(values) - 1)
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
                if i == fault_n:
                    phis_i[fault_k] = ZR.random()
                z = (phis_i, witnesses[i])
                zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
                dispersal_msg_list[i] = zz
                dispersal_msg_list[i] = zz

            return dumps((commitments, ephemeral_public_key)), dispersal_msg_list

    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    sends, recvs, _ = test_router(n)
    # TODO: add configurable crs specifically for poly_commit_log
    crs = [g]

    values = [ZR.random()] * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    with ExitStack() as stack:
        hbavss_list = []
        for i in range(n):
            if i == dealer_id:
                hbavss = BadDealer(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            else:
                hbavss = Hbacss0(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            hbavss_list.append(hbavss)
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()
    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )
    assert recovered_values == values


@mark.asyncio
async def test_hbacss1(test_router):
    from pypairing import G1, ZR
    #from honeybadgermpc.betterpairing import G1, ZR
    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    #g, h, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)
    crs = gen_pc_const_dl_crs(t, g=g)
    pc = PolyCommitConstDL(crs)

    values = [ZR.random()] * 2 * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    shares = [None] * n
    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss1(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )

    assert recovered_values == values

@mark.asyncio
async def test_hbacss1_share_fault(test_router):
    from pypairing import G1, ZR
    #from honeybadgermpc.betterpairing import G1, ZR
    # Injects one invalid share
    class BadDealer(Hbacss1):
        def _get_dealer_msg(self, values, n):
            # Sample B random degree-(t) polynomials of form φ(·)
            # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
            # The same as B (batch_size)
            fault_n = randint(1, n - 1)
            fault_k = randint(1, len(values) - 1)
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
                if i == fault_n:
                    phis_i[fault_k] = ZR.random()
                z = (phis_i, witnesses[i])
                zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
                dispersal_msg_list[i] = zz
                dispersal_msg_list[i] = zz

            return dumps((commitments, ephemeral_public_key)), dispersal_msg_list

    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    #g, h, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)
    crs = gen_pc_const_dl_crs(t, g=g)
    pc = PolyCommitConstDL(crs)

    values = [ZR.random()] * 3 * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    with ExitStack() as stack:
        hbavss_list = []
        for i in range(n):
            if i == dealer_id:
                hbavss = BadDealer(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            else:
                hbavss = Hbacss1(pks, sks[i], crs, n, t, i, sends[i], recvs[i],pc=pc)
            hbavss_list.append(hbavss)
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()
    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )
    assert recovered_values == values

@mark.asyncio
async def test_hbacss2(test_router):
    from pypairing import G1, ZR
    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    sends, recvs, _ = test_router(n)
    # TODO: add configurable crs specifically for poly_commit_log
    crs = [g]

    values = [ZR.random()] * 2 * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    shares = [None] * n
    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss2(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )

    assert recovered_values == values

@mark.asyncio
async def test_hbacss2_share_fault(test_router):
    from pypairing import G1, ZR
    from honeybadgermpc.share_recovery import poly_lagrange_at_x, poly_interpolate_at_x
    # Injects one invalid share
    class BadDealer(Hbacss2):
        def _get_dealer_msg(self, values, n):
            # Notice we currently required the number of values shared to be divisible by t+1.
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
            redundant_poly_witnesses = [self.poly_commit.double_batch_create_witness(psis[i::(n - (self.t + 1))], r) for
                                        i
                                        in
                                        range(n - (self.t + 1))]
            fault_i = randint(1, n - 1)
            # fault_i = 4
            fault_k = randint(1, secret_count - 1)
            for i in range(n):
                shared_key = pow(self.public_keys[i], ephemeral_secret_key)
                orig_shares = [phis[k](i + 1) for k in range(secret_count)]
                if i == fault_i:
                    orig_shares[fault_k] = ZR.random()
                # redundant_shares = [psis[k](i + 1) for k in range(redundant_poly_count)]
                # Redundant shares are not required to send.
                z = (orig_shares, [orig_poly_witnesses[j][i] for j in range(self.t + 1)],
                     [redundant_poly_witnesses[j][i] for j in range(n - (self.t + 1))])
                zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
                dispersal_msg_list[i] = zz

            return dumps((orig_poly_commitments, redundant_poly_commitments, ephemeral_public_key)), dispersal_msg_list

    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    sends, recvs, _ = test_router(n)
    # TODO: add configurable crs specifically for poly_commit_log
    crs = [g]

    values = [ZR.random()] * 2 * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    with ExitStack() as stack:
        hbavss_list = []
        for i in range(n):
            if i == dealer_id:
                hbavss = BadDealer(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            else:
                hbavss = Hbacss2(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            hbavss_list.append(hbavss)
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )
    # print(values)
    # print("\n\n\n\n")
    assert recovered_values == values


