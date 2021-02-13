from pytest import mark
# from honeybadgermpc.betterpairing import ZR
from pypairing import ZR
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
import cProfile

long_param_list_t = [1,
                     2,
                     3,
                     4,
                     5,
                     6,
                     7,
                     8,
                     9,
                     10,
                     11,
                     12,
                     13,
                     14,
                     15,
                     16,
                     17,
                     18,
                     19,
                     20,
                     21,
                     22,
                     23,
                     24,
                     25,
                     26,
                     27,
                     28,
                     29,
                     30,
                     31,
                     32,
                     33,
                     34,
                     35,
                     36,
                     37,
                     38,
                     39,
                     40,
                     41,
                     42]

"""
@mark.parametrize("t", [3, 10, 20, 33])
def test_benchmark_commit(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phi = polynomials_over(ZR).random(t)
    benchmark(pc.commit, phi, r)
@mark.parametrize("t", [3, 10, 20, 33])
def test_benchmark_create_witness(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phi = polynomials_over(ZR).random(t)
    benchmark(pc.create_witness, phi, r, 3)
@mark.parametrize("t", [3, 10, 20, 33])
def test_benchmark_create_batch_witness(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phi = polynomials_over(ZR).random(t)
    pc.preprocess_prover()
    benchmark(pc.batch_create_witness, phi, r, n=3 * t + 1)
@mark.parametrize("t", [3, 10, 20, 33])
def test_benchmark_double_create_batch_witness_10_polys(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phis = []
    for _ in range(10):
        phis.append(polynomials_over(ZR).random(t))
    pc.preprocess_prover()
    benchmark(pc.double_batch_create_witness, phis, r, n=(3 * t + 1)*len(phis))
@mark.parametrize("t", [10,20,30,40,50])
def test_benchmark_double_create_batch_witness_10_polys(benchmark, t):
    pc = PolyCommitLog(degree_max=10)
    r = ZR.random()
    phis = []
    for _ in range(t):
        phis.append(polynomials_over(ZR).random(10))
    pc.preprocess_prover()
    benchmark(pc.double_batch_create_witness, phis, r, n=(3 * 10 + 1)*len(phis))
@mark.parametrize("t", [10, 20, 30, 40, 50, 60, 70])
def test_benchmark_create_batch_witness(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phi = polynomials_over(ZR).random(t)
    pc.preprocess_prover()
    benchmark(pc.batch_create_witness, phi, r, n=3 * t + 1)
@mark.parametrize("t", [10, 20, 30, 40, 50, 60, 70])
def test_benchmark_double_create_batch_witness_10_polys(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phis = []
    for _ in range(20):
        phis.append(polynomials_over(ZR).random(t))
    pc.preprocess_prover()
    benchmark(pc.double_batch_create_witness, phis, r, n=(3 * t + 1)*len(phis))
@mark.parametrize("t", [10, 20, 30, 40, 50, 60, 70])
def test_benchmark_verify_10_polys(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phis = []
    r = ZR.random()
    cs = []
    for _ in range(t):
        phi_curr = polynomials_over(ZR).random(t)
        phis.append(phi_curr)
        c_curr = pc.commit(phi_curr, r)
        cs.append(c_curr)
    witnesses = pc.double_batch_create_witness(phis, r)
    benchmark(pc.verify_eval, cs[0], 4, phis[0](4), witnesses[0][3])
"""


@mark.parametrize("t", long_param_list_t)
def test_benchmark_batch_verify(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    pc.preprocess_verifier(16)
    phis = []
    r = ZR.random()
    cs = []
    for _ in range(6 *(t + 1)):
        phi_curr = polynomials_over(ZR).random(t)
        phis.append(phi_curr)
        c_curr = pc.commit(phi_curr, r)
        cs.append(c_curr)
    witnesses = pc.double_batch_create_witness(phis, r)

    i = 4
    phis_at_4 = []
    for j in range(len(phis)):
        phis_at_4.append(phis[j](i))
    # assert pc.batch_verify_eval(cs, i, phis_at_4, witnesses[i-1])
    benchmark(pc.batch_verify_eval, cs, i, phis_at_4, witnesses[i - 1])


@mark.parametrize("t", long_param_list_t)
def test_benchmark_batch_creation(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    pc.preprocess_prover(16)
    r = ZR.random()
    phis = []
    for _ in range(6 * (t + 1)):
        phi_curr = polynomials_over(ZR).random(t)
        phis.append(phi_curr)
    benchmark(pc.double_batch_create_witness, phis, r)

#
# @mark.parametrize("polycount", [1, 3, 10, 33, 100, 200])
# def test_benchmark_prover_dbatch_vary_poly(benchmark, polycount):
#     t = 20
#     pc = PolyCommitLog(degree_max=t)
#     pc.preprocess_prover()
#     r = ZR.random()
#     phis = []
#     cs = []
#     for _ in range(polycount):
#         phi_curr = polynomials_over(ZR).random(t)
#         phis.append(phi_curr)
#     benchmark(pc.double_batch_create_witness, phis, r)


if __name__ == "__main__":
    t = 20
    # t = 2
    pc = PolyCommitLog(degree_max=t)
    pc.preprocess_prover()
    phis = []
    r = ZR.random()
    cs = []
    for _ in range(6 * (t + 1)):
        phi_curr = polynomials_over(ZR).random(t)
        phis.append(phi_curr)
        c_curr = pc.commit(phi_curr, r)
        cs.append(c_curr)
    # cProfile.run("pc.double_batch_create_witness(phis, r)")
    witnesses = pc.double_batch_create_witness(phis, r)
    i = 4
    phis_at_4 = []
    for j in range(len(phis)):
        phis_at_4.append(phis[j](i))
    assert pc.batch_verify_eval(cs, i, phis_at_4, witnesses[i - 1])
    # print(len(witnesses))
    # print(len(witnesses[1]))
