from pypairing import G1, ZR, Curve25519G, Curve25519ZR
from pickle import dumps, loads

def gen_lookup():
    serializer_lookup = {}
    #[type, size (if applicable)]
    serializer_lookup[b'\x01'] = ["list_start", -1]
    serializer_lookup[b'\x02'] = ["list_end", -1]
    serializer_lookup[b'\x03'] = ["tuple_start", -1]
    serializer_lookup[b'\x04'] = ["tuple_end", -1]
    serializer_lookup[b'\x05'] = [G1, 48]
    serializer_lookup[b'\x06'] = [ZR, 32]
    serializer_lookup[b'\x07'] = [Curve25519G, 32]
    serializer_lookup[b'\x08'] = [Curve25519ZR, 32]
    serializer_lookup[b'\x09'] = [bytes, -1]
    serializer_lookup[b'\x99'] = ["misc", -1]
    
    return serializer_lookup

def gen_reverse_lookup():
    serializer_lookup = gen_lookup()
    serializer_reverse_lookup = {}
    for key, value in serializer_lookup.items():
        serializer_reverse_lookup[value[0]] = key
    return serializer_reverse_lookup

def deserialize(bytestr):
    lookup = gen_lookup()
    _, output = deserialize_item(bytestr, 0, lookup)
    return output

def deserialize_item(bytestr, seek, lookup):
    #bytestr[seek] returns an int apparently
    type, size = lookup[bytestr[seek:seek+1]]
    seek += 1
    if type == "list_start":
        return deserialize_iter(bytestr, seek, lookup, "list")
    elif type == "tuple_start":
        return deserialize_iter(bytestr, seek, lookup, "tuple")
    elif type == bytes:
        size = bytestr[seek]
        seek +=1
        object = bytestr[seek:seek+size]
    elif type == "misc":
        size = bytestr[seek]
        seek +=1
        object = loads(bytestr[seek:seek+size])
    else:
        object = type()
        object.__setstate__(bytestr[seek:seek+size])
    return [seek+size, object]

def deserialize_iter(bytestr, seek, lookup, iter_type):
    output = []
    while True:
        if lookup[bytestr[seek:seek+1]][0] == "list_end" or lookup[bytestr[seek:seek+1]][0] == "tuple_end":
            if iter_type == "tuple":
                output = tuple(output)
            return [seek+1, output]
        elif lookup[bytestr[seek:seek+1]][0] == "list_start":
            seek, object =  deserialize_iter(bytestr, seek+1, lookup, "list")
            output.append(object)
        elif lookup[bytestr[seek:seek+1]][0] == "tuple_start":
            seek, object =  deserialize_iter(bytestr, seek+1, lookup, "tuple")
            output.append(object)
        else:
            seek, object = deserialize_item(bytestr, seek, lookup)
            output.append(object)

def serialize(item):
    lookup = gen_reverse_lookup()
    return serialize_item(item, lookup)

def serialize_item(item, lookup):
    if type(item) is list or type(item) is tuple:
        return serialize_iter(item, lookup)
    elif type(item) is bytes:
        return lookup[type(item)] + bytes([len(item)]) + item
    elif type(item) in lookup:
        return lookup[type(item)] + item.__getstate__()
    else:
        dump = dumps(item)
        return b'\x99' + bytes([len(dump)]) + dump

def serialize_iter(item, lookup):
    output = b""
    lookup["list_start"]
    for entry in item:
        if type(entry) is list:
            output += serialize_iter(entry, lookup)
        else:
            output += serialize_item(entry, lookup)
    if type(item) is list:
        return lookup["list_start"] + output + lookup["list_end"]
    if type(item) is tuple:
        return lookup["tuple_start"] + output + lookup["tuple_end"]
        
        