import pypairing
from pytest import mark
from contextlib import ExitStack
from random import randint
from adkg.betterpairing import ZR, G1
from adkg.polynomial import polynomials_over
from adkg.poly_commit_log import PolyCommitLog
from adkg.poly_commit_dummy import PolyCommitAMTDummy, PolyCommitLoglinDummy
from adkg.hbavss import Hbacss0, Hbacss1, Hbacss2, HbAVSSMessageType
from adkg.field import GF
from adkg.utils.misc import print_exception_callback, wrap_send, subscribe_recv
from adkg.router import SimpleRouter
import asyncio
from adkg.symmetric_crypto import SymmetricCrypto
import logging
import time
import cProfile

short_param_list_t = [1,
                      2,
                      5,
                      10,
                      22,
                      42]

def get_avss_params(n, t):
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

class Hbacss2_always_accept_implicates(Hbacss2):
    async def _handle_implication(self, tag, j, j_sk):
        await super()._handle_implication(tag, j, j_sk)
        return True


class Hbacss2_always_send_and_accept_implicates(Hbacss2_always_accept_implicates):
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg):
        super()._handle_dealer_msgs(tag, dispersal_msg, rbc_msg)
        return False

async def hbacss2_pcl_all_correct(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)
    # pcl = PolyCommitLog(degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss2(pks, sks[i], crs, n, t, i, sends[i], recvs[i],
                             pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "t",
    short_param_list_t,
)
def test_hbacss2_pcl_all_correct(benchmark_router, benchmark, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * 6 * (t+1) * (t+1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss2_pcl_all_correct(benchmark_router, params))

    benchmark(_prog)


async def hbacss2_pcl_max_faulty_shares(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    fault_is = [i for i in range(t, t+t)]
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = None
            if i not in fault_is:
                hbavss = Hbacss2_always_accept_implicates(pks, sks[i], crs, n, t, i, sends[i], recvs[i],
                                                          pc=pcl)
            else:
                hbavss = Hbacss2_always_send_and_accept_implicates(pks, sks[i], crs, n, t, i, sends[i],
                                                                   recvs[i], pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "t",
    short_param_list_t,
)
def test_hbacss2_pcl_max_faulty_shares(benchmark_router, benchmark, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * 6 * (t+1) * (t+1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss2_pcl_max_faulty_shares(benchmark_router, params))

    benchmark(_prog)
