from pytest import mark
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.share_recovery import interpolate_g1_at_x
# from honeybadgermpc.poly_commit_feldman import PolyCommitFeldman
from honeybadgermpc.poly_commit_hybrid import PolyCommitHybrid
from honeybadgermpc.poly_commit_bulletproof_blind import PolyCommitBulletproofBlind
from honeybadgermpc.adkg import ADKG
import asyncio
import uvloop
import time
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
from pypairing import Curve25519ZR as ZR, Curve25519G as G1


def get_avss_params(n, t):
    gs = G1.hash_many(b"honeybadgerg", 2*t+1)
    hs = G1.hash(b"honeybadgerh")
    u = G1.hash(b"honeybadgeru")
    crs = [gs, hs, u]
    g, h = gs[0], G1.hash(b'h')   
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.hash(bytes(i))
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys, crs


@mark.asyncio
@mark.parametrize("t",[3])
async def test_adkg(test_router, t):
    # from pypairing import ZR
    # t = 1
    n = 3 * t + 1

    g, h, pks, sks, crs = get_avss_params(n, t)
    sends, recvs, _ = test_router(n, maxdelay=0.001)
    pc = PolyCommitBulletproofBlind(crs, 2*t)
    pc2 = PolyCommitHybrid(crs, 2*t)
    # h.preprocess(8)
    # pc.preprocess_prover()
    # pc2.preprocess_prover()

    start_time = time.time()
    dkg_tasks = [None] * n # async task for adkg
    dkg_list = [None] * n #

    for i in range(n):
        dkg = ADKG(pks, sks[i], g, h, n, t, i, sends[i], recvs[i], pc, pc2)
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
    pk_shares = []
    i = 1
    for _, _, sk, _ in outputs:
        shares.append([i, sk])
        pk_shares.append([i, h**sk])
        i = i + 1

    poly = polynomials_over(ZR)
    msk = poly.interpolate_at(shares,0)
    mpk2 = interpolate_g1_at_x(pk_shares,0)
    mpk = h**msk
    assert  mpk == mpk2

    for i in range(n):
        assert(mpk == outputs[i][3])

    mks_set = outputs[0][1]
    for i in range(1, n):
        assert mks_set == outputs[i][1]

    msk_sum = ZR(0)
    for node in mks_set:
        msk_sum = msk_sum + outputs[node][0]
    assert msk_sum == msk