from collections import defaultdict
import logging
import hashlib
import math
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


class RBCMsgType:
    PROPOSE = 1
    ECHO = 2
    READY = 3
    TERMINATE = 4
    ADD_TRIGGER = 5
    ADD_DISPERSE = 6
    ADD_RECONSTRUCT = 7

async def optqrbc(
    sid, pid, n, f, leader, predicate, input, send, receive):
    """
    Validated Quadradatic Reliable Broadcast from DXL21 
    """
    assert n >= 3 * f + 1
    assert f >= 0
    assert 0 <= leader < n
    assert 0 <= pid < n

    k = f + 1  # Wait to reconstruct. (# noqa: E221)
    echo_threshold = 2 * f +1   # Wait for ECHO to send R. (# noqa: E221)
    ready_threshold = f + 1  # Wait for R to amplify. (# noqa: E221)
    output_threshold = 2 * f + 1  # Wait for this many R to output
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
        
        broadcast((RBCMsgType.PROPOSE, m))
        
    stripes = [None for _ in range(n)]
    echo_counter = defaultdict(lambda: 0)
    ready_counter = defaultdict(lambda: 0)
    echo_senders = set()
    ready_senders = set()
    ready_sent = False
    ready_digest = None
    leader_hash = None
    reconstructed_hash = None
    leader_msg = None
    reconstructed_msg = None

    add_ready_sent = False
    terminate_senders = set()
    add_trigger_senders = set()
    add_disperse_senders = set()
    add_reconstruct_senders = set()
    add_disperse_counter = defaultdict(lambda: 0)
    committed_hash = None
    committed = False

    while True:  # main receive loop
            sender, msg = await receive()
            if msg[0] == RBCMsgType.PROPOSE and leader_hash is None:
                (_, leader_msg) = msg
                if sender != leader:
                    logger.info(f"[{pid}] PROPOSE message from other than leader: {sender}")
                    continue
            
                valid = await predicate(leader_msg)
                if valid:
                    leader_hash = hash(leader_msg)
                    broadcast((RBCMsgType.ECHO, leader_hash))
                    if leader_hash == committed_hash:
                        broadcast((RBCMsgType.TERMINATE))
                    
            if msg[0] == RBCMsgType.ECHO:
                (_, _digest) = msg
                if sender in echo_senders:
                    # Received redundant ECHO message from the same sender
                    continue
                echo_senders.add(sender)
                echo_counter[_digest] = echo_counter[_digest]+1
                
                if echo_counter[_digest] >= echo_threshold and not ready_sent:
                    ready_sent = True
                    broadcast((RBCMsgType.READY, ready_digest))
            
            elif msg[0] == RBCMsgType.READY:
                (_, _digest) = msg
                if sender in ready_senders:
                    logger.info("[{pid}] Redundant R")
                    continue
                ready_senders.add(sender)
                ready_counter[_digest] = ready_counter[_digest]+1
                if ready_counter[_digest] >= ready_threshold and not ready_sent:
                    ready_sent = True
                    broadcast((RBCMsgType.READY, _digest))
                
                if ready_counter[_digest] >= output_threshold:
                    committed_hash = _digest
                    if _digest == leader_hash:
                        committed = True
                        broadcast((RBCMsgType.TERMINATE))
                    elif _digest == reconstructed_hash:
                        committed = True
                        broadcast((RBCMsgType.TERMINATE))
                    else:
                        broadcast((RBCMsgType.ADD_TRIGGER))
                        

            elif msg[0] == RBCMsgType.TERMINATE:
                if sender in terminate_senders:
                    logger.info("[{pid}] Redundant TERMINATE")
                    continue
                terminate_senders.add(sender)
                if len(terminate_senders) >= n:
                    if committed_hash == leader_hash:
                        return leader_msg
                    elif committed_hash == reconstructed_hash:
                        return reconstructed_msg
                    else:
                        logger.info("[{pid}] RBC ERROR")

 
            elif msg[0] == RBCMsgType.ADD_TRIGGER:
                if sender in add_trigger_senders:
                    logger.info("[{pid}] Redundant ADD_TRIGGER")
                    continue
                add_trigger_senders.add(sender)
                if committed:
                    stripes = encode(k,n,m)
                    send(sender, (RBCMsgType.ADD_DISPERSE, stripes[sender], stripes[pid]))

            elif msg[0] == RBCMsgType.ADD_DISPERSE:
                if committed:
                    continue
                (_, my_stripe, sender_stripe) = msg
                if sender in add_disperse_senders:
                    logger.info("[{pid}] Redundant ADD_DISPERSE")
                    continue
                add_disperse_senders.add(sender)
                add_reconstruct_senders.add(sender)
                add_disperse_counter[my_stripe] = add_disperse_counter[my_stripe]+1
                stripes[sender] = sender_stripe

                if add_disperse_senders[my_stripe] >= f + 1 and not add_ready_sent:
                    add_ready_sent = True
                    broadcast((RBCMsgType.ADD_RECONSTRUCT, my_stripe))

            elif msg[0] == RBCMsgType.ADD_RECONSTRUCT:
                if committed:
                    continue
                (_, stripe) = msg
                if sender in add_reconstruct_senders:
                    logger.info("[{pid}] Redundant ADD_RECONSTRUCT")
                    continue
                add_reconstruct_senders.add(sender)
                stripes[sender] = stripe
                
                if len(add_reconstruct_senders) >= output_threshold:
                    reconstructed_msg = decode(k, n, stripes)
                    reconstructed_hash = hash(reconstructed_msg)
                    if reconstructed_hash == committed_hash:
                        broadcast((RBCMsgType.TERMINATE))