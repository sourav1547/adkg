from pypairing import Curve25519ZR as ZR, Curve25519G as G1

def serialize_g(g):
    return bytes(g.__getstate__())

def deserialize_g(data):
    g = G1()
    g.__setstate__(list(data))
    return g

def deserialize_gs(data):
    g_size = 32
    n = len(data)//g_size
    gs = []
    for i in range(n):            
        g = G1()
        g.__setstate__(list(data[i*g_size:(i+1)*g_size]))
        gs.append(g)
    return gs

def serialize_gs(g_list):    
    n = len(g_list)
    data = bytearray()
    for i in range(n):
        g = g_list[i]
        data.extend(bytes(g.__getstate__()))
    return data

def serialize_f(f):
    return bytes(f.__getstate__())

def deserialize_f(data):
    f = ZR()
    f.__setstate__(list(data))
    return f

# Not tested yet
def serialize_fs(f_list):    
    n = len(f_list)
    f_size = 32 # Only valid for ed25519, to change this for bls12381
    data = bytearray(n*f_size)
    for i in range(n):
        f = f_list[i]
        data[i*f_size] = bytes(f.__getstate__())
    return data


