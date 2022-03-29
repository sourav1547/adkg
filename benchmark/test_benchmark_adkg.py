from pytest import mark
from adkg.polynomial import polynomials_over
from adkg.poly_commit_feldman import PolyCommitFeldman
from adkg.adkg import adkg
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

@mark.parametrize("t", [1])
def test_benchmark_adkg(test_router, benchmark, t):
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    sends, recvs, _ = test_router(n, maxdelay=0.001)

    g, h, pks, sks = get_avss_params(n, t)
    pc = PolyCommitFeldman(g)
    
    params = (sends, recvs, t, n, g, h, pks, sks, pc)

    def _prog():
        loop.run_until_complete(run_adkg(params))

    benchmark(_prog)


async def run_adkg(params):
    (sends, recvs, t, n, g, h, pks, sks, pc)  = params

    dkg_tasks = [None] * n # async task for adkg
    dkg_list = [None] * n #

    for i in range(n):
        dkg = adkg(pks, sks[i], g, h, n, t, i, sends[i], recvs[i], pc)
        dkg_list[i] = dkg
        dkg_tasks[i] = asyncio.create_task(dkg.run_adkg())
    
    await asyncio.gather(
        *[dkg_list[i].output_queue.get() for i in range(n)]
    )
    for task in dkg_tasks:
        task.cancel()