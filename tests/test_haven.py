from pytest import mark
from random import randint
from pickle import dumps
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_feldman import PolyCommitFeldman
from honeybadgermpc.poly_commit_bulletproof import PolyCommitBulletproof
from honeybadgermpc.poly_commit_bulletproof_blind import PolyCommitBulletproofBlind
from honeybadgermpc.poly_commit_hybrid import PolyCommitHybrid
from honeybadgermpc.haven import HavenAVSS, HybridHavenAVSS
from honeybadgermpc.utils.misc import print_exception_callback
import asyncio


@mark.asyncio
@mark.parametrize(
    "t, p, n",
    [
        (2, 2, 7),
        (2, 3, 7),
        (3, 6, 10),
        (3, 6, 12)
    ])
async def test_haven(test_router, t, p, n):
    #from pypairing import G1, ZR
    from pypairing import Curve25519ZR as ZR, Curve25519G as G1

    g = G1.rand()
    sends, recvs, _ = test_router(n)
    #pc = PolyCommitFeldman(g)
    pc = PolyCommitBulletproof()

    value = ZR.random()
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    shares = [None] * n
    haven_list = [None] * n
    for i in range(n):
        haven = HavenAVSS(n, t, p, i, sends[i], recvs[i], pc)
        haven_list[i] = haven
        if i == dealer_id:
            avss_tasks[i] = asyncio.create_task(haven.avss(0, value=value))
        else:
            avss_tasks[i] = asyncio.create_task(haven.avss(0, dealer_id=dealer_id))
        avss_tasks[i].add_done_callback(print_exception_callback)
    outputs = await asyncio.gather(
        *[haven_list[i].output_queue.get() for i in range(n)]
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

    assert recovered_values == [value]
    for haven in haven_list:
        haven.kill()

@mark.asyncio
@mark.parametrize(
    "t, p, n",
    [
        (2, 2, 7),
        (2, 3, 7),
        (3, 6, 10),
        (3, 6, 12)
    ])
async def test_haven_hybrid(test_router, t, p, n):
    #from pypairing import G1, ZR
    from pypairing import Curve25519ZR as ZR, Curve25519G as G1

    g = G1.hash(b"honeybadgerg")
    sends, recvs, _ = test_router(n)
    #pc = PolyCommitFeldman(g)
    pc = PolyCommitBulletproofBlind()
    pc2 = PolyCommitHybrid()

    value = ZR.random()
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    shares = [None] * n
    haven_list = [None] * n
    for i in range(n):
        haven = HybridHavenAVSS(n, t, p, i, sends[i], recvs[i], pc, pc2)
        haven_list[i] = haven
        if i == dealer_id:
            avss_tasks[i] = asyncio.create_task(haven.avss(0, value=value))
        else:
            avss_tasks[i] = asyncio.create_task(haven.avss(0, dealer_id=dealer_id))
        avss_tasks[i].add_done_callback(print_exception_callback)
    outputs = await asyncio.gather(
        *[haven_list[i].output_queue.get() for i in range(n)]
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

    assert recovered_values == [value]
    for haven in haven_list:
        haven.kill()