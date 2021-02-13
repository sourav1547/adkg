from pytest import mark
from honeybadgermpc.betterpairing import ZR
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
import pickle
import cProfile


t = 21
pc = PolyCommitLog(degree_max=t)
r = ZR.random()
phis = []
r = ZR.random()
cs = []
for _ in range(3*t+1):
    phi_curr = polynomials_over(ZR).random(t)
    phis.append(phi_curr)
    c_curr = pc.commit(phi_curr, r)
    cs.append(c_curr)
cProfile.run("pc.double_batch_create_witness(phis, r)")
