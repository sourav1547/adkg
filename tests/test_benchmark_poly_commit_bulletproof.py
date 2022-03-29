from pytest import mark
# from adkg.betterpairing import ZR
from pypairing import Curve25519ZR as ZR
from adkg.polynomial import polynomials_over
from adkg.poly_commit_bulletproof import PolyCommitBulletproof
import cProfile


@mark.parametrize(
    "degree, n",
    [
        (2, 7),
        (4, 7),
        (10, 31),
        (20, 31)
    ])
def test_benchmark_batch_prove(benchmark, degree, n):
    pc = PolyCommitBulletproof(degree_max=degree)
    pc.preprocess_prover(8)
    phi = polynomials_over(ZR).random(degree)
    c = pc.commit(phi)
    benchmark(pc.batch_create_witness, c, phi, n)

@mark.parametrize(
    "degree, n",
    [
        (2, 7),
        (4, 7)
    ])
def test_benchmark_batch_prove_no_preprocessing(benchmark, degree, n):
    pc = PolyCommitBulletproof(degree_max=degree)
    phi = polynomials_over(ZR).random(degree)
    c = pc.commit(phi)
    benchmark(pc.batch_create_witness, c, phi, n)

@mark.parametrize(
    "degree",
    [2, 4, 10, 20])
def test_benchmark_verify(benchmark, degree):
    pc = PolyCommitBulletproof(degree_max=degree)
    phi = polynomials_over(ZR).random(degree)
    c = pc.commit(phi)
    i = 5
    eval = phi(i)
    w = pc.create_witness(c, phi, i)
    benchmark(pc.verify_eval, c, i, eval, w)

@mark.parametrize(
    "degree",
    [2, 4, 10, 20])
def test_benchmark_verify_no_preprocessing(benchmark, degree):
    pc = PolyCommitBulletproof(degree_max=degree)
    pc.preprocess_verifier(8)
    phi = polynomials_over(ZR).random(degree)
    c = pc.commit(phi)
    i = 5
    eval = phi(i)
    w = pc.create_witness(c, phi, i)
    benchmark(pc.verify_eval, c, i, eval, w)


if __name__ == "__main__":
    degree = 20
    pc = PolyCommitBulletproof(degree_max=degree)
    phi = polynomials_over(ZR).random(degree)
    c = pc.commit(phi)
    i = 5
    eval = phi(i)
    w = pc.batch_create_witness(c, phi, 31)
    #cProfile.run("w = pc.batch_create_witness(c, phi, 31)")
    assert pc.verify_eval(c, i, eval, w[i-1])
    #cProfile.run("pc.verify_eval(c, i, eval, w)")
    