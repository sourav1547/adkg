from pytest import mark
# from honeybadgermpc.betterpairing import ZR
from pypairing import ZR
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
import cProfile

short_param_list_t = [1,
                      2,
                      5,
                      10,
                      22,
                      42]


@mark.parametrize("t", short_param_list_t)
def test_hbacss2_size_benchmark_batch_creation(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    pc.preprocess_prover(16)
    r = ZR.random()
    phis = []
    for _ in range(t):
        phi_curr = polynomials_over(ZR).random(t)
        phis.append(phi_curr)
    benchmark(pc.double_batch_create_witness, phis, r)

@mark.parametrize("t", short_param_list_t)
def test_hbacss2_size_benchmark_batch_verify(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    pc.preprocess_verifier(16)
    phis = []
    r = ZR.random()
    cs = []
    for _ in range(t):
        phi_curr = polynomials_over(ZR).random(t)
        phis.append(phi_curr)
        c_curr = pc.commit(phi_curr, r)
        cs.append(c_curr)
    witnesses = pc.double_batch_create_witness(phis, r)

    i = 4
    phis_at_4 = []
    for j in range(len(phis)):
        phis_at_4.append(phis[j](i))
    benchmark(pc.batch_verify_eval, cs, i, phis_at_4, witnesses[i - 1])