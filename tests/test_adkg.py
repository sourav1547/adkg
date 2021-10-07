from pytest import mark
from random import randint
from contextlib import ExitStack
from pickle import dumps
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_feldman import PolyCommitFeldman
from honeybadgermpc.acss import Hbacss0SingleShare
from honeybadgermpc.adkg import adkg
#from adkg.mpc import TaskProgramRunner
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.utils.misc import print_exception_callback
import asyncio


def get_avss_params(n, t):
    from pypairing import G1, ZR
    g = G1.rand()
    h = G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


@mark.asyncio
async def test_adkg(test_router):
    from pypairing import G1, ZR
    t = 1
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)
    pc = PolyCommitFeldman(g)

    dkg_tasks = [None] * n # async task for adkg
    dkg_list = [None] * n #

    for i in range(n):
        dkg = adkg(pks, sks[i], g, h, n, t, i, sends[i], recvs[i], pc)
        dkg_list[i] = dkg
        dkg_tasks[i] = asyncio.create_task(dkg.run_adkg())
        dkg_tasks[i].add_done_callback(print_exception_callback)
    outputs = await asyncio.gather(
        *[dkg_list[i].output_queue.get() for i in range(n)]
    )
    for task in dkg_tasks:
        task.cancel()
    for dkg in dkg_list:
        dkg.kill()
    assert True