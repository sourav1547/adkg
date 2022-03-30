import logging
from pytest import mark
from random import randint
from adkg.polynomial import polynomials_over
from adkg.acss_dcr import ACSS_DCR
from adkg.utils.misc import print_exception_callback
import asyncio
import phe


def get_avss_params(n, t):
    from pypairing import G1, ZR
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    g = G1.rand()
    keypairs = [phe.paillier.generate_paillier_keypair() for _ in range(n)]
    public_keys, private_keys = [[keypairs[i][j] for i in range(n)] for j in range(2)]
    return g, public_keys, private_keys


@mark.asyncio
async def test_acss_dcr(test_router):
    from pypairing import G1, ZR
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    t = 1
    n = 3 * t + 1

    g, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)

    secret = ZR.random()
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    shares = [None] * n
    hbavss_list = [None] * n
    for i in range(n):
        hbavss = ACSS_DCR(pks, sks[i], g, n, t, i, sends[i], recvs[i])
        hbavss_list[i] = hbavss
        if i == dealer_id:
            avss_tasks[i] = asyncio.create_task(hbavss.avss(0, secret=secret))
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

    assert recovered_values == [secret]