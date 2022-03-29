import asyncio
from pytest import mark

from adkg.poly_commit_const_dl import PolyCommitConstDL, gen_pc_const_dl_crs
#from adkg.betterpairing import ZR
from pypairing import ZR
from adkg.polynomial import polynomials_over
from adkg.utils.misc import print_exception_callback
from adkg.share_recovery import HbACSS1Recoverer

@mark.asyncio
async def test_HbACSS1Recoverer(test_router):
    t = 2
    n = 3*t + 1
    poly = polynomials_over(ZR)
    secrets = [ZR.random() for i in range(t+1)]
    secretpolys = [poly.random(t, secrets[i]) for i in range(t+1)]
    crs = gen_pc_const_dl_crs(t)
    pc = PolyCommitConstDL(crs)
    commits = [pc.commit(phi) for phi in secretpolys]
    #witnesses[i][j] should give the proof for party i's share of polynomial number j
    witnesses = [ [pc.create_witness(phi, i) for phi in secretpolys] for i in range(1,n+1)]
    shares = [ [phi(i) for phi in secretpolys] for i in range(1,n+1)]
    sends, recvs, _ = test_router(n)

    loop = asyncio.get_event_loop()
    players = [ HbACSS1Recoverer(crs, n, t, i, sends[i], recvs[i], shares[i], True, commits, witnesses[i], pc=pc) for i in range(n)]
    playertasks = [loop.create_task(player._run()) for player in players]
    for task in playertasks:
        task.add_done_callback(print_exception_callback)
    #loop.run_forever()
    await asyncio.gather(*playertasks)