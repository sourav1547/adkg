from pytest import mark
from random import randint
from contextlib import ExitStack
from pickle import dumps
from adkg.polynomial import polynomials_over
from adkg.acss_dcr import ACSS_DCR
#from honeybadgermpc.mpc import TaskProgramRunner
from adkg.misc import print_exception_callback
import asyncio
import phe
#from pypairing import G1, ZR
from pypairing import Curve25519ZR as ZR, Curve25519G as G1

def get_avss_params(n, t):
    g = G1.rand()
    keypairs = [phe.paillier.generate_paillier_keypair() for _ in range(n)]
    public_keys, private_keys = [[keypairs[i][j] for i in range(n)] for j in range(2)]
    return g, public_keys, private_keys


@mark.parametrize(
    "t, n",
    [
        (2, 7),
        (5, 16),
        (10, 31)
    ],
)
def test_benchmark_acss_dcr(test_router, benchmark, n, t):
    loop = asyncio.get_event_loop()
    async def get_acss_list(test_router, n, t):
        g, pks, sks = get_avss_params(n, t)
        sends, recvs, _ = test_router(n)
        # initialize all the acss instances and do any precomp
        hbavss_list = [ACSS_DCR(pks, sks[i], g, n, t, i, sends[i], recvs[i]) for i in range(n)]
        return hbavss_list

    hbavss_list = loop.run_until_complete(get_acss_list(test_router, n, t))

    def _prog():
        loop.run_until_complete(acss_prog(test_router, n, t, hbavss_list))

    benchmark(_prog)

async def acss_prog(test_router, n, t, hbavss_list):
    secret = ZR.random()
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    sid = randint(0, 314159265358979)
    shares = [None] * n
    for i in range(n):
        hbavss = hbavss_list[i]
        if i == dealer_id:
            avss_tasks[i] = asyncio.create_task(hbavss.avss(sid, secret=secret))
        else:
            avss_tasks[i] = asyncio.create_task(hbavss.avss(sid, dealer_id=dealer_id))
        avss_tasks[i].add_done_callback(print_exception_callback)
    '''
    # this line seems to hang if you're calling acss_prog more than once (as you would in this benchmark)
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

    assert recovered_values == [secret]
    '''    