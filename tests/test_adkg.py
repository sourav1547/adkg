from pytest import mark
from adkg.polynomial import polynomials_over
from adkg.poly_commit_feldman import PolyCommitFeldman
from adkg.adkg import ADKG
import asyncio
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
from pypairing import ZR, G1
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    
import time

def get_avss_params(n, G1):
    from phe import PaillierPublicKey, PaillierPrivateKey
    g, h = G1.hash(b'g'), G1.hash(b'h') 
    public_keys = [None for _ in range(n)]
    private_keys = [None for _ in range(n)]
    with open("apps/tutorial/keys", 'r') as kfile:
        keys = kfile.readlines()
        for i in range(n):
            data = keys[i].split(' ')
            public_keys[i] = PaillierPublicKey(int(data[0]))
            private_keys[i] = PaillierPrivateKey(public_keys[i], int(data[1]), int(data[2]))
    return g, h, public_keys, private_keys

@mark.asyncio
async def test_adkg(test_router):
    t = 1
    deg = 2*t
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params(n, G1)
    sends, recvs, _ = test_router(n, maxdelay=0.001)
    pc = PolyCommitFeldman(g)

    dkg_tasks = [None] * n # async task for adkg
    dkg_list = [None] * n #

    start_time = time.time()

    for i in range(n):
        dkg = ADKG(pks, sks[i], g, h, n, t, deg, i, sends[i], recvs[i], pc, ZR, G1)
        dkg_list[i] = dkg
        dkg_tasks[i] = asyncio.create_task(dkg.run_adkg(start_time))
    
    outputs = await asyncio.gather(
        *[dkg_list[i].output_queue.get() for i in range(n)]
    )
    for dkg in dkg_list:
        dkg.kill()
    for task in dkg_tasks:
        task.cancel()
    
    
    shares = []
    i = 1
    for _, _, sk, _ in outputs:
        shares.append([i, sk])
        i = i + 1

    poly = polynomials_over(ZR)
    msk = poly.interpolate_at(shares,0)
    mpk = h**msk

    for i in range(n):
        assert(mpk == outputs[i][3])

    mks_set = outputs[0][1]
    for i in range(1, n):
        assert mks_set == outputs[i][1]

    msk_sum = ZR(0)
    for node in mks_set:
        msk_sum = msk_sum + outputs[node][0]
    assert msk_sum == msk