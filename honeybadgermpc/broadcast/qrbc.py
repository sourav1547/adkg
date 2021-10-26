from collections import defaultdict
import logging
import hashlib
import math
from honeybadgermpc.polynomial import EvalPoint
from honeybadgermpc.reed_solomon import (
    FFTEncoder,
    FFTDecoder,
    GaoRobustDecoder,
)

from honeybadgermpc.field import GF
from honeybadgermpc.elliptic_curve import Subgroup

import zfec


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)


#####################
# def encode(k, n, m):
#     """Erasure encodes string ``m`` into ``n`` blocks, such that any ``k``
#     can reconstruct.
#     :param int k: k
#     :param int n: number of blocks to encode string ``m`` into.
#     :param bytes m: bytestring to encode.
#     :return list: Erasure codes resulting from encoding ``m`` into
#         ``n`` blocks using ``zfec`` lib.
#     """
#     try:
#         m = m.encode()
#     except AttributeError:
#         pass
#     field = GF(Subgroup.BLS12_381)
#     point = EvalPoint(field, n, use_omega_powers=True)
#     # encoder = zfec.Encoder(k, n)
#     assert k <= 256  # TODO: Record this assumption!
#     # pad m to a multiple of K bytes
#     padlen = k - (len(m) % k)
#     m += padlen * chr(k - padlen).encode()
#     step = len(m) // k
#     blocks = [m[i * step : (i + 1) * step] for i in range(k)]
#     enc = FFTEncoder(point)
#     stripes = enc.encode(blocks)
#     decode(k,n, stripes)
#     return stripes



# def decode(k, n, stripes):
#     """Decodes an erasure-encoded string from a subset of stripes
#     :param list stripes: a container of :math:`n` elements,
#         each of which is either a string or ``None``
#         at least :math:`k` elements are strings
#         all string elements are the same length
#     """
#     assert len(stripes) == n
#     blocks = []
#     blocknums = []
#     for i, block in enumerate(stripes):
#         if block is None:
#             continue
#         blocks.append(block)
#         blocknums.append(i)
#         if len(blocks) == k:
#             break
#     else:
#         raise ValueError("Too few to recover")
#     field = GF(Subgroup.BLS12_381)
#     point = EvalPoint(field, n, use_omega_powers=True)
#     decoder = FFTDecoder(point)
#     # decoder = zfec.Decoder(k, n)
#     rec = decoder.decode(blocks, blocknums)
#     m = b"".join(rec)
#     padlen = k - m[-1]
#     m = m[:-padlen]
#     return m


#    zfec encode    #
#####################
def encode(k, n, m):
    """Erasure encodes string ``m`` into ``n`` blocks, such that any ``k``
    can reconstruct.
    :param int k: k
    :param int n: number of blocks to encode string ``m`` into.
    :param bytes m: bytestring to encode.
    :return list: Erasure codes resulting from encoding ``m`` into
        ``n`` blocks using ``zfec`` lib.
    """
    try:
        m = m.encode()
    except AttributeError:
        pass
    encoder = zfec.Encoder(k, n)
    assert k <= 256  # TODO: Record this assumption!
    # pad m to a multiple of K bytes
    padlen = k - (len(m) % k)
    m += padlen * chr(k - padlen).encode()
    step = len(m) // k
    blocks = [m[i * step : (i + 1) * step] for i in range(k)]
    stripes = encoder.encode(blocks)
    return stripes


def decode(k, n, stripes):
    """Decodes an erasure-encoded string from a subset of stripes
    :param list stripes: a container of :math:`n` elements,
        each of which is either a string or ``None``
        at least :math:`k` elements are strings
        all string elements are the same length
    """
    assert len(stripes) == n
    blocks = []
    blocknums = []
    for i, block in enumerate(stripes):
        if block is None:
            continue
        blocks.append(block)
        blocknums.append(i)
        if len(blocks) == k:
            break
    else:
        raise ValueError("Too few to recover")
    decoder = zfec.Decoder(k, n)
    rec = decoder.decode(blocks, blocknums)
    m = b"".join(rec)
    padlen = k - m[-1]
    m = m[:-padlen]
    return m


def hash(x):
    assert isinstance(x, (str, bytes))
    try: 
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()

def ceil(x):
    return int(math.ceil(x))


async def qrbc(
    sid, pid, n, f, leader, predicate, input, send, receive, client_mode=False
):
    """
    Validated Quadradatic Reliable Broadcast from DXL21 
    """
    assert n >= 3 * f + 1
    assert f >= 0
    assert 0 <= leader < n
    assert 0 <= pid < n

    k = 2 * f + 1  # Wait to reconstruct. (# noqa: E221)
    echo_threshold = n - f  # Wait for ECHO to send READY. (# noqa: E221)
    ready_threshold = f + 1  # Wait for READY to amplify. (# noqa: E221)
    output_threshold = 2 * f + 1  # Wait for this many READY to output
    # NOTE: The above thresholds  are chosen to minimize the size
    # of the erasure coding stripes, i.e. to maximize K.
    # The following alternative thresholds are more canonical
    # (e.g., in Bracha '86) and require larger stripes, but must wait
    # for fewer nodes to respond
    #   EchoThreshold = ceil((N + f + 1.)/2)
    #   K = EchoThreshold - f

    def broadcast(o):
        for i in range(n):
            send(i, o)

    
    if pid == leader:
        m = input

        assert isinstance(m, (str, bytes))
        logger.debug("[%d] Input received: %d bytes" % (pid, len(m)))

        for i in range(n):
            send(i, ("PROPOSE", m))
        
        if client_mode:
            return

    stripes = defaultdict(lambda: [None for _ in range(n)])
    echo_counter = defaultdict(lambda: 0)
    echo_senders = set()
    ready_senders = set()
    ready_sent = False
    from_leader = None
    ready_digest = None

    while True:  # main receive loop
            sender, msg = await receive()
            if msg[0] == "PROPOSE" and from_leader is None:
                (_, m) = msg
                if sender != leader:
                    logger.info(f"[{pid}] PROPOSE message from other than leader: {sender}")
                    continue
            
                valid = await predicate(m)
                if valid:
                    _digest = hash(m)
                    _stripes = encode(k,n, m)
                    from_leader = _digest
                    for i in range(n):
                        send(i, ("ECHO", _digest, _stripes[i]))
                    
            if msg[0] == "ECHO":
                (_, _digest, stripe) = msg
                if sender in echo_senders:
                    # Received redundant ECHO message from the same sender
                    continue
                echo_senders.add(sender)
                echo_counter[stripe] = echo_counter[stripe]+1

                # TODO: Have to match the digest as well.
                if echo_counter[stripe] >= f + 1:
                    ready_stripe = stripe
                    ready_digest = _digest
                
                if len(echo_senders) >= echo_threshold and not ready_sent:
                    ready_sent = True
                    broadcast(("READY", ready_digest, ready_stripe))
            
            elif msg[0] == "READY":
                (_, _digest, stripe) = msg
                # Validation
                if sender in ready_senders:
                    logger.info("[{pid}] Redundant READY")
                    continue
                    
                ready_senders.add(sender)
                stripes[_digest][sender] = stripe
                if len(ready_senders) >= ready_threshold and not ready_sent:
                    if ready_digest is not None:
                        ready_sent = True
                        broadcast((sid, "READY", ready_digest, ready_stripe))
                
                if len(ready_senders) >= output_threshold:
                    m = decode(k, n, stripes[_digest])
                    # FIXME: I have to handle padding
                    if ready_digest == hash(m):
                        return m

                
            

            
        
                
            
            

        

            
            
            

            # Update 

            