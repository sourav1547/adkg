from pytest import mark
from random import randint
from contextlib import ExitStack
from pickle import dumps
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_feldman import PolyCommitFeldman
from honeybadgermpc.acss import Hbacss0SingleShare
#from adkg.mpc import TaskProgramRunner
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.utils.misc import print_exception_callback
import asyncio


def get_avss_params(n, t):
    from pypairing import G1, ZR
    g = G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, public_keys, private_keys


@mark.asyncio
async def test_hbacss0(test_router):
    from pypairing import G1, ZR
    t = 2
    n = 3 * t + 1

    g, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)
    pc = PolyCommitFeldman(g)

    values = [ZR.random()]
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    shares = [None] * n
    hbavss_list = [None] * n
    for i in range(n):
        hbavss = Hbacss0SingleShare(pks, sks[i], g, n, t, i, sends[i], recvs[i], pc)
        hbavss_list[i] = hbavss
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