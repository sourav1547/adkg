from honeybadgermpc.proofs import (
    prove_inner_product,
    verify_inner_product,
    prove_inner_product_one_known,
    verify_inner_product_one_known,
    prove_batch_inner_product_one_known,
    verify_batch_inner_product_one_known,
    MerkleTree,
)
from honeybadgermpc.proofs_interactive import (
    inner_product_prover,
    inner_product_verifier,
)
from pypairing import ZR, G1
import asyncio


def test_inner_product_interactive_proof():

    loop = asyncio.get_event_loop()
    pr_queue = asyncio.Queue(loop=loop)
    vr_queue = asyncio.Queue(loop=loop)
    prover = inner_product_prover(vr_queue, pr_queue)
    verifier = inner_product_verifier(pr_queue, vr_queue)

    n = 10
    a = [ZR.random() for i in range(n)]
    b = [ZR.random() for i in range(n)]
    iprod = ZR(0)
    for i in range(n):
        iprod += a[i] * b[i]

    (comm1, iprod1, g_vec1, h_vec1, u1, a_vec1, b_vec1, n1, P1) = prover.set_up_params(a, b)
    (g_vec2, h_vec2, u2, n2, P2) = verifier.set_up_params(n1, P1)
    prover_coro = prover.recursive_prove(g_vec1, h_vec1, u1, a_vec1, b_vec1, n1, P1)
    verifier_coro = verifier.recursive_verify(g_vec2, h_vec2, u2, n2, P2)
    _, ret =loop.run_until_complete(asyncio.gather(prover_coro, verifier_coro))
    assert ret == True

    (_, _, g_vec1, h_vec1, u1, a_vec1, b_vec1, n1, P1) = prover.set_up_params(a, b, comm=comm1)
    (g_vec2, h_vec2, u2, n2, P2) = verifier.set_up_params(n1, P1)
    prover_coro = prover.recursive_prove(g_vec1, h_vec1, u1, a_vec1, b_vec1, n1, P1)
    verifier_coro = verifier.recursive_verify(g_vec2, h_vec2, u2, n2, P2)
    _, ret = loop.run_until_complete(asyncio.gather(prover_coro, verifier_coro))
    assert ret == True

    (comm1, iprod1, g_vec1, h_vec1, u1, a_vec1, b_vec1, n1, P1) = prover.set_up_params(a, b, comm=G1.rand())
    (g_vec2, h_vec2, u2, n2, P2) = verifier.set_up_params(n1, P1)
    prover_coro = prover.recursive_prove(g_vec1, h_vec1, u1, a_vec1, b_vec1, n1, P1)
    verifier_coro = verifier.recursive_verify(g_vec2, h_vec2, u2, n2, P2)
    _, ret = loop.run_until_complete(asyncio.gather(prover_coro, verifier_coro))
    assert ret == False
    loop.close()

