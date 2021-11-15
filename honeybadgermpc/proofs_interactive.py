#from honeybadgermpc.betterpairing import ZR, G1
# from pypairing import ZR, G1
from pypairing import Curve25519ZR as ZR, Curve25519G as G1
from honeybadgermpc.proofs import MerkleTree
import pickle
import math
import hashlib
import asyncio
import random


# Interactive Version for a normal inner product prover
class inner_product_prover:
    def __init__(self, send_queue, receive_queue):
        self.send_queue = send_queue
        self.receive_queue = receive_queue

    def set_up_params(self, a_vec, b_vec, comm=None, crs=None):
        n = len(a_vec)
        assert len(b_vec) == n
        if crs is None:
            g_vec = G1.hash_many(b"honeybadgerg", n)
            h_vec = G1.hash_many(b"honeybadgerh", n)
            u = G1.hash(b"honeybadgeru")
        else:
            [g_vec, h_vec, u] = crs
            g_vec = g_vec[:n]
            h_vec = h_vec[:n]
        if comm is not None:
            P = comm * G1.identity()
        else:
            comm = G1.identity()
            for i in range(n):
                comm *= g_vec[i] ** a_vec[i] * h_vec[i] ** b_vec[i]
        iprod = ZR(0)
        for i in range(n):
            iprod += a_vec[i] * b_vec[i]
        P = comm * u ** iprod
        return (comm, iprod, g_vec,h_vec,u,a_vec,b_vec,n,P)

    async def recursive_prove(self, g_vec, h_vec, u, a_vec, b_vec, n, P):
        if n == 1:
            await self.send_queue.put([a_vec[0], b_vec[0]])
            return

        proofStep = []
        if n % 2 == 1:
            na, nb =  a_vec[-1] * -1, b_vec[-1] * -1
            P *= g_vec[-1] ** (na) * h_vec[-1] ** (nb) * u ** (-na * nb)
            proofStep.append(na)
            proofStep.append(nb)

        n_p = n // 2
        cl = ZR(0)
        cr = ZR(0)
        L = G1.identity()
        R = G1.identity()
        for i in range(n_p):
            cl += a_vec[:n_p][i] * b_vec[n_p:][i]
            cr += a_vec[n_p:][i] * b_vec[:n_p][i]
            L *= g_vec[n_p:][i] ** a_vec[:n_p][i] * h_vec[:n_p][i] ** b_vec[n_p:][i]
            R *= g_vec[:n_p][i] ** a_vec[n_p:][i] * h_vec[n_p:][i] ** b_vec[:n_p][i]
        L *= u ** cl
        R *= u ** cr

        proofStep.append(L)
        proofStep.append(R)
        await self.send_queue.put(proofStep)
        x = await self.receive_queue.get()

        xi = x**-1
        g_vec_p, h_vec_p, a_vec_p, b_vec_p = [], [], [], []
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i] ** xi * g_vec[n_p:][i] ** x)
            h_vec_p.append(h_vec[:n_p][i] ** x * h_vec[n_p:][i] ** xi)
            a_vec_p.append(a_vec[:n_p][i] * x + a_vec[n_p:][i] * xi)
            b_vec_p.append(b_vec[:n_p][i] * xi + b_vec[n_p:][i] * x)
        P_p = L ** (x * x) * P * R ** (xi * xi)

        await self.recursive_prove(
            g_vec_p, h_vec_p, u, a_vec_p, b_vec_p, n_p, P_p
         )
        return

# Interactive Version for a normal inner product verifier
class inner_product_verifier:
    def __init__(self, send_queue, receive_queue):
        self.send_queue = send_queue
        self.receive_queue = receive_queue

    def set_up_params(self, n, P, crs=None):
        if crs is None:
            g_vec = G1.hash_many(b"honeybadgerg", n)
            h_vec = G1.hash_many(b"honeybadgerh", n)
            u = G1.hash(b"honeybadgeru")
        else:
            [g_vec, h_vec, u] = crs
        return (g_vec, h_vec, u, n, P)

    async def recursive_verify(self, g_vec, h_vec, u, n, P):
        if n == 1:
            [a, b] = await self.receive_queue.get()
            return P == g_vec[0] ** a * h_vec[0] ** b * u ** (a * b)
        if n % 2 == 1:
            [na, nb, L, R] = await self.receive_queue.get()
            P *= g_vec[-1] ** (na) * h_vec[-1] ** (nb) * u ** (-na * nb)
        else:
            [L, R] = await self.receive_queue.get()
        x = ZR.random()
        await self.send_queue.put(x)
        xi = x**-1
        n_p = n // 2
        g_vec_p = []
        h_vec_p = []
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i] ** xi * g_vec[n_p:][i] ** x)
            h_vec_p.append(h_vec[:n_p][i] ** x * h_vec[n_p:][i] ** xi)
        P_p = L ** (x * x) * P * R ** (xi * xi)
        ret = await self.recursive_verify(g_vec_p, h_vec_p, u, n_p, P_p)
        return ret

'''
# Inner product prover where one vector (b_vec) is known by both parties
class inner_product_one_known_prover:
    def __init__(self, send_queue, receive_queue):
        self.send_queue = send_queue
        self.receive_queue = receive_queue

    def set_up_params(self, a_vec, b_vec, comm=None, crs=None):
        n = len(a_vec)
        assert len(b_vec) == n
        if crs is None:
            g_vec = G1.hash_many(b"honeybadgerg", n)
            u = G1.hash(b"honeybadgeru")
        else:
            [g_vec, u] = crs
            g_vec = g_vec[:n]
        if comm is not None:
            P = comm * G1.one()
        else:
            comm = G1.one()
            for i in range(n):
                comm *= g_vec[i] ** a_vec[i]
        iprod = ZR(0)
        for i in range(n):
            iprod += a_vec[i] * b_vec[i]
        P = comm * u ** iprod
        return (comm, iprod, g_vec, a_vec, b_vec, u, n, P)

    async def recursive_proof(self, g_vec, a_vec, b_vec, u, n, P):
        if n == 1:
            await self.send_queue([a_vec[0]])
            return
        proofstep = []
        if n % 2 == 1:
            na = -1 * a_vec[-1]
            P *= g_vec[-1] ** (na) * u ** (na * b_vec[-1])
            proofstep.append(na)
        n_p = n // 2
        cl = ZR(0)
        cr = ZR(0)
        L = G1.one()
        R = G1.one()
        for i in range(n_p):
            cl += a_vec[:n_p][i] * b_vec[n_p:][i]
            cr += a_vec[n_p:][i] * b_vec[:n_p][i]
            L *= g_vec[n_p:][i] ** a_vec[:n_p][i]
            R *= g_vec[:n_p][i] ** a_vec[n_p:][i]
        L *= u ** cl
        R *= u ** cr
        proofstep.append(L)
        proofstep.append(R)
        await self.send_queue.put(proofStep)
        x = await self.receive_queue.get()
        xi = 1 / x
        g_vec_p, a_vec_p, b_vec_p = [], [], []
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i] ** xi * g_vec[n_p:][i] ** x)
            a_vec_p.append(a_vec[:n_p][i] * x + a_vec[n_p:][i] * xi)
            b_vec_p.append(b_vec[:n_p][i] * xi + b_vec[n_p:][i] * x)
        P_p = L ** (x * x) * P * R ** (xi * xi)
        await recursive_proof(g_vec_p, a_vec_p, b_vec_p, u, n_p, P_p)
        return

# Inner product verifier where one vector (b_vec) is known by both parties
class inner_product_one_known_verifier:
    def __init__(self, send_queue, receive_queue):
        self.send_queue = send_queue
        self.receive_queue = receive_queue

    def set_up_params(self, b_vec, n, P, crs=None):
        if crs is None:
            g_vec = G1.hash_many(b"honeybadgerg", n)
            u = G1.hash(b"honeybadgeru")
        else:
            [g_vec, u] = crs
            g_vec = g_vec[:n]
        return (g_vec, b_vec, u, n, P)

    def recursive_verify(self, g_vec, b_vec, u, proof, n, P):
        if n == 1:
            [a, b] = await self.receive_queue.get()
            return P == g_vec[0] ** a * u ** (a * b)
        if n % 2 == 1:
            [na, L, R] = await self.receive_queue.get()
            P *= g_vec[-1] ** (na) * u ** (na * b_vec[-1])
        else:
            [L, R] = await self.receive_queue.get()
        x = ZR.random()
        await self.send_queue.put(x)
        xi = 1 / x
        n_p = n // 2
        g_vec_p = []
        b_vec_p = []
        for i in range(n_p):
            g_vec_p.append(g_vec[:n_p][i] ** xi * g_vec[n_p:][i] ** x)
            b_vec_p.append(b_vec[:n_p][i] * xi + b_vec[n_p:][i] * x)
        P_p = L ** (x * x) * P * R ** (xi * xi)
        ret = await recursive_verify(g_vec_p, b_vec_p, u, n_p, P_p)
        return ret
'''