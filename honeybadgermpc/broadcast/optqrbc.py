from collections import defaultdict
import logging
import hashlib
import math
from reedsolo import RSCodec, ReedSolomonError
import numpy as np
import asyncio

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)


# NOTE: This is not very optimized as it is never triggered in the normal case operation
def encode(k, n, m):
    """encodes string ``m`` into ``n`` blocks, such that any ``k``
    can reconstruct.
    :param int k: k
    :param int n: number of blocks to encode string ``m`` into.
    :param bytes m: bytestring to encode.
    :return list: Return encoding of ``m`` into
        ``n`` blocks using ``reedsolo`` lib.
    """
    rsc = RSCodec(n-k)
    padlen = k - (len(m) % k)
    m += padlen * chr(k - padlen).encode()
    mlen = len(m)//k
    blocks = [m[i * k : (i + 1) * k] for i in range(mlen)]
    
    stripes = [None]*mlen
    for i in range(mlen):
        stripes[i] = rsc.encode(blocks[i])

    nstripes = np.array(stripes)
    return nstripes.T

# NOTE: This is not very optimized as it is never triggered in the normal case operation
def decode(k, n, stripes):
    """Decodes an error corrected encoded string from a subset of stripes
    :param list stripes: a container of :math:`n` elements,
        each of which is either a string or ``None``
        at least :math:`k` elements are strings
        all string elements are the same length
    """
    rsc = RSCodec(n-k)
    elen = len(list(stripes.values())[0])
    
    erasure_pos = []
    columns = []
    
    for i in range(n):
        if i in stripes:
            columns.append(stripes[i])
        else:
            zeros = np.array([0]*elen)
            columns.append(zeros)
            erasure_pos.append(i)
            
    code_words = np.array(columns).T
    message = []
    for val in code_words:
        message.append(rsc.decode(list(val))[0])
        
    m = list(np.array(message).flatten())
    padlen = k - m[-1]
    m = m[:-padlen]
    
    return bytes(m)
        
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


async def optqrbc(sid, pid, n, f, leader, predicate, input, output, send, receive):
    """
    Implementation of Validated Reliable Broadcast from DXL21 with good case optimization.
    Briefly, the protocol proceeds as follows:
    1. Broadcaster sends the proposal to all
    2. Nodes run Bracha's RBC on hash
    3. Node i output once the RBC on hash terminates and if it has received a matching proposal from leader
    4. Otherwise, node i triggers a fallback protocol that uses ADD to help node i recover the proposal.
    """
    assert n >= 3 * f + 1
    assert f >= 0
    assert 0 <= leader < n
    assert 0 <= pid < n

    k = f + 1  # Wait to reconstruct. (# noqa: E221)
    echo_threshold = 2 * f +1   # Wait for ECHO to send R. (# noqa: E221)
    ready_threshold = f + 1  # Wait for R to amplify. (# noqa: E221)
    output_threshold = 2 * f + 1  # Wait for this many R to output

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

                    # TODO: double check this
                    if leader_hash == committed_hash:
                        broadcast((RBCMsgType.TERMINATE, 0))
                    
            if msg[0] == RBCMsgType.ECHO:
                (_, _digest) = msg
                if sender in echo_senders:
                    # Received redundant ECHO message from the same sender
                    continue
                echo_senders.add(sender)
                echo_counter[_digest] = echo_counter[_digest]+1
                
                if echo_counter[_digest] >= echo_threshold and not ready_sent:
                    ready_sent = True
                    broadcast((RBCMsgType.READY, _digest))
            
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
                        output(leader_msg)
                        broadcast((RBCMsgType.TERMINATE, 0))
                    elif _digest == reconstructed_hash:
                        committed = True
                        output(reconstructed_msg)  
                        broadcast((RBCMsgType.TERMINATE, 0))
                    else:
                        broadcast((RBCMsgType.ADD_TRIGGER, 0))
                        

            elif msg[0] == RBCMsgType.TERMINATE:
                if sender in terminate_senders:
                    logger.info("[{pid}] Redundant TERMINATE")
                    continue
                terminate_senders.add(sender)
                if len(terminate_senders) == n:
                    return

 
            elif msg[0] == RBCMsgType.ADD_TRIGGER:
                if sender in add_trigger_senders:
                    logger.info("[{pid}] Redundant ADD_TRIGGER")
                    continue
                add_trigger_senders.add(sender)
                if committed:
                    if stripes is None:
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
                        committed = True
                        output(reconstructed_msg)  
                        broadcast((RBCMsgType.TERMINATE, 0))