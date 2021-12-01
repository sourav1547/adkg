# from pypairing import Curve25519ZR as ZR, Curve25519G as G1
from pypairing import G1, ZR

def serialize_g(g):
    return g.__getstate__()

def deserialize_g(data):
    g = G1()
    g.__setstate__(data)
    return g

def deserialize_gs(data):
    g_size = 48
    n = len(data)//g_size
    gs = [None for _ in range(n)]
    for i in range(n):            
        g = G1()
        g.__setstate__(data[i*g_size:(i+1)*g_size])
        gs[i] = g
    return gs

def serialize_gs(g_list):    
    n = len(g_list)
    data = bytearray()
    for i in range(n):
        g = g_list[i]
        data.extend(g.__getstate__())
    return data

def serialize_f(f):
    return f.__getstate__()

def deserialize_f(data):
    f = ZR()
    f.__setstate__(data)
    return f

# Not tested yet
def serialize_fs(f_list):    
    n = len(f_list)
    f_size = 32 # Only valid for ed25519, to change this for bls12381
    data = bytearray(n*f_size)
    for i in range(n):
        f = f_list[i]
        data[i*f_size] = f.__getstate__()
    return data


