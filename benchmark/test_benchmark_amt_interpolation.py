import pypairing
from pytest import mark
from contextlib import ExitStack
from random import randint
from honeybadgermpc.betterpairing import ZR, G1
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
from honeybadgermpc.poly_commit_dummy import PolyCommitAMTDummy, PolyCommitLoglinDummy, SimulatedPclProof, SimulatedPclCom, SimulatedAMTProof, SimulatedAMTCom, ActualAMTCom, ActualAMTProof, log2, findNextPowerOf2
from honeybadgermpc.field import GF
from honeybadgermpc.utils.misc import print_exception_callback, wrap_send, subscribe_recv
from honeybadgermpc.router import SimpleRouter
import asyncio
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
import logging
import time
import cProfile
from honeybadgermpc.share_recovery import poly_lagrange_at_x, poly_interpolate_at_x, interpolate_g1_at_x
from honeybadgermpc.poly_commit_amt_unity import PolyCommitAMTUnity, get_all_roots_of_unity, bit_reverse, gen_crs

short_param_list_t = [1,
                      2,
                      5,
                      10,
                      22,
                      42]

# async def commit_and_proof_interpolation(params):
#     (t, n, values, commitments, witnesses) = params
    
#     known_commits = commitments
#     known_commit_coords = [[i + 1, ActualAMTCom(known_commits[i])] for i in range(t + 1)]
#     interpolated_commits = [interpolate_g1_at_x(known_commit_coords, i + 1) for i in range(t + 1, n)]

#     # the proofs for the specific shares held by this node
#     known_evalproofs = witnesses
#     known_evalproof_coords = [[i + 1, ActualAMTProof(known_evalproofs[i])] for i in range(t + 1)]
#     interpolated_evalproofs = [interpolate_g1_at_x(known_evalproof_coords, i + 1) for i in
#                             range(t + 1,n)]

async def commit_and_proof_interpolation(params):
    (t, n, values, commitments, witnesses) = params
    
    known_commits = commitments
    _ = [known_commit.preprocess(4) for known_commit in known_commits]
    known_commit_coords = [[i + 1, ActualAMTCom(known_commits[i])] for i in range(t + 1)]
    interpolated_commits = [interpolate_g1_at_x(known_commit_coords, i + 1) for i in range(t + 1, n)]

    # the proofs for the specific shares held by this node
    known_evalproofs = witnesses
    _ = [[g.preprocess(4) for g in known_proof] for known_proof in known_evalproofs]
    known_evalproof_coords = [[i + 1, ActualAMTProof(known_evalproofs[i])] for i in range(t + 1)]
    interpolated_evalproofs = [interpolate_g1_at_x(known_evalproof_coords, i + 1) for i in
                            range(t + 1,n)]

@mark.parametrize(
    "t",
    short_param_list_t,
)
def test_amt_commit_and_proof_interpolation(benchmark_router, benchmark, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    crs = gen_crs(degree_max=128)
    pc = PolyCommitAMTUnity(crs, findNextPowerOf2(n))
    values = [ZR.random() for _ in range((t+1))]
    poly = polynomials_over(ZR)
    secret_count = len(values)
    phis = [None] * secret_count
    commitments = [None] * secret_count
    r = ZR.random()
    for k in range(secret_count):
        phis[k] = poly.random(t, values[k])
        commitments[k] = pc.commit(phis[k])
    
    witnesses = [[pc.create_witness(phis[k], j) for i in range(len(phis))] for j in range(n)][1]

    params = (t, n, values, commitments, witnesses)
    def _prog():
        loop.run_until_complete(commit_and_proof_interpolation(params))

    benchmark(_prog)


