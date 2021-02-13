import pypairing
from pytest import mark
from contextlib import ExitStack
from random import randint
from honeybadgermpc.betterpairing import ZR, G1
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
from honeybadgermpc.poly_commit_dummy import PolyCommitAMTDummy, PolyCommitLoglinDummy
from honeybadgermpc.hbavss import Hbacss0, Hbacss1, Hbacss2, HbAVSSMessageType
from honeybadgermpc.field import GF
from honeybadgermpc.utils.misc import print_exception_callback, wrap_send, subscribe_recv
from honeybadgermpc.router import SimpleRouter
import asyncio
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
import logging
import time
import cProfile

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)

mul_t_param_list = [
    (6, 1),
    (6, 2),
    (6, 5),
    (6, 10),
    (6, 22),
    (6, 42)
]


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


class Hbacss0_always_accept_implicates(Hbacss0):
    async def _handle_implication(self, tag, j, j_sk):
        await super()._handle_implication(tag, j, j_sk)
        return True


class Hbacss0_always_send_and_accept_implicates(Hbacss0_always_accept_implicates):
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg):
        super()._handle_dealer_msgs(tag, dispersal_msg, rbc_msg)
        return False


class Hbacss1_always_accept_implicates(Hbacss1):
    async def _handle_implication(self, tag, j, j_sk):
        await super()._handle_implication(tag, j, j_sk)
        return True


class Hbacss1_always_send_and_accept_implicates(
    Hbacss1_always_accept_implicates):
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg):
        super()._handle_dealer_msgs(tag, dispersal_msg, rbc_msg)
        return False


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
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss2_pcl_all_correct(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss2_pcl_all_correct(benchmark_router, params))

    benchmark(_prog)


# async def hbacss2_pcl_one_faulty_share(benchmark_router, params):
#     (t, n, g, h, pks, sks, crs, values) = params
#     fault_i = randint(1, n - 1)
#     # fault_i = 4
#     fault_k = randint(1, len(values) - 1)
#     sends, recvs, _ = benchmark_router(n)
#     avss_tasks = [None] * n
#     dealer_id = randint(0, n - 1)
#     pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)
#
#     with ExitStack() as stack:
#         hbavss_list = [None] * n
#         for i in range(n):
#             hbavss = None
#             if i != fault_i:
#                 hbavss = Hbacss2_always_accept_implicates(pks, sks[i], crs, n, t, i, sends[i], recvs[i],
#                                                           pc=pcl)
#             else:
#                 hbavss = Hbacss2_always_send_and_accept_implicates(pks, sks[i], crs, n, t, i, sends[i],
#                                                                    recvs[i], pc=pcl)
#             hbavss_list[i] = hbavss
#             stack.enter_context(hbavss)
#             if i == dealer_id:
#                 avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
#             else:
#                 avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
#             avss_tasks[i].add_done_callback(print_exception_callback)
#         await asyncio.gather(
#             *[hbavss_list[i].output_queue.get() for i in range(n)]
#         )
#         for task in avss_tasks:
#             task.cancel()
#
#
# @mark.parametrize(
#     "batch_multiple, t",
#     mul_t_param_list,
# )
# def test_hbacss2_pcl_one_faulty_share(benchmark_router, benchmark, batch_multiple, t):
#     from pypairing import G1, ZR
#     loop = asyncio.get_event_loop()
#     n = 3 * t + 1
#     g, h, pks, sks = get_avss_params_pyp(n, t)
#     values = [ZR.random()] * batch_multiple * (t + 1)
#     crs = [g]
#     params = (t, n, g, h, pks, sks, crs, values)
#
#     def _prog():
#         loop.run_until_complete(hbacss2_pcl_one_faulty_share(benchmark_router, params))
#
#     benchmark(_prog)


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
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss2_pcl_max_faulty_shares(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss2_pcl_max_faulty_shares(benchmark_router, params))

    benchmark(_prog)


async def hbacss1_pcl_all_correct(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss1(pks, sks[i], crs, n, t, i,
                             sends[i],
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
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss1_pcl_all_correct(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss1_pcl_all_correct(benchmark_router, params))

    benchmark(_prog)


# async def hbacss1_pcl_one_faulty_share(benchmark_router, params):
#     (t, n, g, h, pks, sks, crs, values) = params
#     fault_i = randint(1, n - 1)
#     # fault_i = 4
#     # fault_k = randint(1, len(values) - 1)
#     sends, recvs, _ = benchmark_router(n)
#     avss_tasks = [None] * n
#     dealer_id = randint(0, n - 1)
#     pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)
#
#     with ExitStack() as stack:
#         hbavss_list = [None] * n
#         for i in range(n):
#             hbavss = None
#             if i != fault_i:
#                 hbavss = Hbacss1_always_accept_implicates(pks, sks[i], crs, n, t, i, sends[i],
#                                                           recvs[i],
#                                                           pc=pcl)
#             else:
#                 hbavss = Hbacss1_always_send_and_accept_implicates(pks, sks[i], crs, n, t, i,
#                                                                    sends[i],
#                                                                    recvs[i], pc=pcl)
#             hbavss_list[i] = hbavss
#             stack.enter_context(hbavss)
#             if i == dealer_id:
#                 avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
#             else:
#                 avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
#             avss_tasks[i].add_done_callback(print_exception_callback)
#         await asyncio.gather(
#             *[hbavss_list[i].output_queue.get() for i in range(n)]
#         )
#         for task in avss_tasks:
#             task.cancel()
#
#
# @mark.parametrize(
#     "batch_multiple, t",
#     mul_t_param_list,
# )
# def test_hbacss1_pcl_one_faulty_share(benchmark_router, benchmark, batch_multiple, t):
#     from pypairing import G1, ZR
#     loop = asyncio.get_event_loop()
#     n = 3 * t + 1
#     g, h, pks, sks = get_avss_params_pyp(n, t)
#     values = [ZR.random()] * batch_multiple * (t + 1)
#     crs = [g]
#     params = (t, n, g, h, pks, sks, crs, values)
#
#     def _prog():
#         loop.run_until_complete(hbacss1_pcl_one_faulty_share(benchmark_router, params))
#
#     benchmark(_prog)


async def hbacss1_pcl_max_faulty_shares(benchmark_router, params):
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
                hbavss = Hbacss1_always_accept_implicates(pks, sks[i], crs, n, t, i,
                                                          sends[i],
                                                          recvs[i],
                                                          pc=pcl)
            else:
                hbavss = Hbacss1_always_send_and_accept_implicates(pks, sks[i], crs, n, t,
                                                                   i,
                                                                   sends[i],
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
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss1_pcl_max_faulty_shares(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss1_pcl_max_faulty_shares(benchmark_router, params))

    benchmark(_prog)


async def hbacss0_pcl_all_correct(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    fault_i = randint(1, n - 1)
    # fault_i = 4
    # fault_k = randint(1, len(values) - 1)
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss0(pks, sks[i], crs, n, t, i, sends[i],
                             recvs[i],
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
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss0_pcl_all_correct(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss0_pcl_all_correct(benchmark_router, params))

    benchmark(_prog)


# async def hbacss0_pcl_one_faulty_share(benchmark_router, params):
#     (t, n, g, h, pks, sks, crs, values) = params
#     fault_i = randint(1, n - 1)
#     fault_i = 4
#     # fault_k = randint(1, len(values) - 1)
#     sends, recvs, _ = benchmark_router(n)
#     avss_tasks = [None] * n
#     dealer_id = randint(0, n - 1)
#     pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)
#
#     with ExitStack() as stack:
#         hbavss_list = [None] * n
#         for i in range(n):
#             hbavss = None
#             if i != fault_i:
#                 hbavss = Hbacss0_always_accept_implicates(pks, sks[i], crs, n, t, i, sends[i],
#                                                           recvs[i],
#                                                           pc=pcl)
#             else:
#                 hbavss = Hbacss0_always_send_and_accept_implicates(pks, sks[i], crs, n, t, i,
#                                                                    sends[i],
#                                                                    recvs[i], pc=pcl)
#             hbavss_list[i] = hbavss
#             stack.enter_context(hbavss)
#             if i == dealer_id:
#                 avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
#             else:
#                 avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
#             avss_tasks[i].add_done_callback(print_exception_callback)
#         await asyncio.gather(
#             *[hbavss_list[i].output_queue.get() for i in range(n)]
#         )
#         for task in avss_tasks:
#             task.cancel()
#
#
# @mark.parametrize(
#     "batch_multiple, t",
#     mul_t_param_list,
# )
# def test_hbacss0_pcl_one_faulty_share(benchmark_router, benchmark, batch_multiple, t):
#     from pypairing import G1, ZR
#     loop = asyncio.get_event_loop()
#     n = 3 * t + 1
#     g, h, pks, sks = get_avss_params_pyp(n, t)
#     values = [ZR.random()] * batch_multiple * (t + 1)
#     crs = [g]
#     params = (t, n, g, h, pks, sks, crs, values)
#
#     def _prog():
#         loop.run_until_complete(hbacss0_pcl_one_faulty_share(benchmark_router, params))
#
#     benchmark(_prog)


async def hbacss0_pcl_max_faulty_shares(benchmark_router, params):
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
                hbavss = Hbacss0_always_accept_implicates(pks, sks[i], crs, n, t, i,
                                                          sends[i],
                                                          recvs[i],
                                                          pc=pcl)
            else:
                hbavss = Hbacss0_always_send_and_accept_implicates(pks, sks[i], crs, n, t,
                                                                   i,
                                                                   sends[i],
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
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss0_pcl_max_faulty_shares(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss0_pcl_max_faulty_shares(benchmark_router, params))

    benchmark(_prog)






# # main function to be used with kernprof
# if __name__ == "__main__":
#     from pypairing import G1, ZR
#     def benchmark_router(n):
#         router = SimpleRouter(n)
#         return router.sends, router.recvs, router.broadcasts
#
#
#     loop = asyncio.get_event_loop()
#     t = 33
#     batch_multiple = 11
#     n = 3 * t + 1
#     g, h, pks, sks = get_avss_params_pyp(n, t)
#     values = [ZR.random()] * batch_multiple * (t + 1)
#     crs = [g]
#     params = (t, n, g, h, pks, sks, crs, values)
#     # loop.run_until_complete(hbacss2_pcl_all_correct(benchmark_router, params))
#     loop.run_until_complete(hbacss1_pcl_max_faulty_shares(benchmark_router, params))