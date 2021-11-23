"""
NOTE: Some part of the code are reused from https://github.com/tyurek/hbACSS
"""

import asyncio
from collections import defaultdict
import logging

from honeybadgermpc.exceptions import RedundantMessageError, AbandonedNodeError
from honeybadgermpc.broadcast.commoncoin import shared_coin


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)

class ABAMsgType:
    AUX = 1
    AUX2 = 2
    EST = 3
    EST2 = 4
    AUXSET = 5
    ABA_COIN  = 6

def handle_auxset_messages(*, sender, message, auxset_values, pid, auxset_signal):
    # _, r, v = message
    _, w, r = parse_msg(message)
    v = None
    if w == 0:
        v = (0,)
    elif w == 1:
        v = (1,)
    elif w == 2:
        v = (0,1)

    assert v in ((0,), (1,), (0,1))
    if sender in auxset_values[r][v]:
        logger.warning(
            f"[{pid}] Redundant AUXSET received {message} by {sender}",
            extra={"nodeid": pid, "epoch": r},
        )
        # FIXME: Raise for now to simplify things & be consistent
        # with how other TAGs are handled. Will replace the raise
        # with a continue statement as part of
        # https://github.com/initc3/HoneyBadgerBFT-Python/issues/10
        raise RedundantMessageError("Redundant AUXSET received {}".format(message))

    auxset_values[r][v].add(sender)
    logger.debug(
        f"[{pid}] add v = {v} to auxset_value[{r}] = {auxset_values[r]}",
        extra={"nodeid": pid, "epoch": r},
    )

    auxset_signal.set()

async def wait_for_auxset_values(
    *,
    pid,
    n,
    f,
    epoch,
    auxset_sent,
    bin_values,
    values,
    auxset_values,
    auxset_signal,
    broadcast,
):
    auxset_sent[epoch] = True
    logger.debug(
        f"[{pid}] broadcast {('AUXSET', epoch, tuple(values))}",
        extra={"nodeid": pid, "epoch": epoch},
    )

    v = 0
    if values == set((1,)):
        v=1
    elif values == set((0,1)):
        v=2
    broadcast(encode_msg(ABAMsgType.AUXSET,v,epoch))

    while True:
        logger.debug(
            f"[{pid}] looping ... auxset_values[epoch] is: {auxset_values[epoch]}",
            extra={"nodeid": pid, "epoch": epoch},
        )
        if 1 in bin_values[epoch] and len(auxset_values[epoch][(1,)]) >= n - f:
            return 1
        if 0 in bin_values[epoch] and len(auxset_values[epoch][(0,)]) >= n - f:
            return 0
        if (
            sum(
                len(senders)
                for auxset_value, senders in auxset_values[epoch].items()
                if senders and set(auxset_value).issubset(bin_values[epoch])
            )
            >= n - f
        ):
            return 2

        auxset_signal.clear()
        await auxset_signal.wait()


def parse_msg(msg):
    tag = msg%10
    msg = msg//10
    v = msg%10
    r = msg//10
    return (tag, v, r)

def encode_msg(tag, v, r):
    return r*100 + v*10 + tag

async def tylerba(sid, pid, n, f, coin_keys, input_msg, decide, broadcast, receive):
    """ Implementation of Tyler20 ABA. Tyler20 has two nice properties:
        1. If all honest node input 0 to an ABA, then that ABA can terminate without a coin.
        2. An honest node can locally decide that no other honest node would require a coin.
    :param sid: session identifier
    :param pid: my id number
    :param N: the number of parties
    :param f: the number of byzantine parties
    :param coin: a ``common coin(r)`` is called to block until receiving a bit
    :param input: ``input()`` is called to receive an input
    :param decide: ``decide(0)`` or ``decide(1)`` is eventually called
    :param broadcast: broadcast channel
    :param receive: receive channel
    :return: blocks until
    """
    # Messages received are routed to either a shared coin, the broadcast, or AUX
    est_values = defaultdict(lambda: [set(), set()])
    aux_values = defaultdict(lambda: [set(), set()])
    est_values2 = defaultdict(lambda: [set(), set(), set()])
    aux_values2 = defaultdict(lambda: [set(), set(), set()])
    est_sent2 = defaultdict(lambda: [False, False, False])
    auxset_values = defaultdict(lambda: {(0,): set(), (1,): set(), (0, 1): set()})
    auxset_sent = defaultdict(lambda:False)
    est_sent = defaultdict(lambda: [False, False])
    bin_values = defaultdict(set)
    bin_values2 = defaultdict(set)

    # This event is triggered whenever bin_values or aux_values changes
    bv_signal = asyncio.Event()
    aux_signal = asyncio.Event()
    auxset_signal = asyncio.Event()
    coin_init = False

    def coin_bcast(o):
        broadcast(("AC", o))

    coin_recvs = asyncio.Queue()

    async def _coin(r, coin_init):
        from pypairing import G1, ZR
        if not coin_init:
            acss_outputs, rbc_values = await coin_keys()
        
        skj = 0
        coeffs = [G1.identity() for _ in range(f+1)]
        for kk in rbc_values:
            skj = skj + acss_outputs[kk][0][0]
            commitments = acss_outputs[kk][1]
            for i in range(len(coeffs)):
                coeffs[i] = coeffs[i]*commitments[0][i] #TODO: Optimize this
        
        pkj = [G1.identity() for _ in range(n)] #TODO: Optimize this
        for i in range(n):
            exp = ZR(1)
            pkji = G1.identity()
            for j in range(len(coeffs)):
                pkji*=coeffs[j]**exp
                exp *= (i+1)
            pkj[i] = pkji
        bpk = TBLSPublicKey(n, f, pkj[j], pkj)
        bsk = TBLSPrivateKey(n, f, pkj[j], pkj, skj, j)

        # FIXME: Generate coin object only once!
        coin, _ = await shared_coin(
            "COIN" + str(sid), pid, n, f, bpk, bsk, coin_bcast, coin_recvs.get
        )
        b = await coin(r)
        print("Coin requested!!")
        return b


    async def _recv():
        while True: # not finished
            (sender, msg) = await receive()
            tag, v, r = parse_msg(msg)
            logger.debug(
                f"[{pid}] receive {msg} from node {sender}",
                extra={"nodeid": pid, "epoch": r},
            )
            assert sender in range(n)

            if tag == ABAMsgType.ABA_COIN:
                coin_recvs.put_nowait((sender, msg))
            elif tag == ABAMsgType.EST:
                assert v in (0,1)
                if sender in est_values[r][v]:
                    # FIXME: raise or continue? For now will raise just
                    # because it appeared first, but maybe the protocol simply
                    # needs to continue. (@sourav: copying this comment from binaryagreement)
                    print(f"[{pid}] Redundant EST received by {sender}", msg)
                    logger.warning(
                        f"[{pid}] Redundant EST message received by {sender}: {msg}",
                        extra={"nodeid": pid, "epoch": r},
                    )
                    raise RedundantMessageError("Redundant EST received {}".format(msg))
                    # continue
                
                est_values[r][v].add(sender)
                # Relay after reaching first threshold
                if len(est_values[r][v]) >= f+1 and not est_sent[r][v]:
                    est_sent[r][v] = True
                    broadcast(encode_msg(ABAMsgType.EST,v,r))
                    logger.debug(
                        f"[{pid}] broadcast {('EST', r, v)}",
                        extra={"nodeid":pid, "epoch": r},
                    )

                # Output after reaching second threshold
                if len(est_values[r][v]) >= 2*f + 1:
                    logger.debug(
                        f"[{pid}] add v={v} to bin_values[{r}] =[{bin_values[r]}]",
                        extra={"nodeid": pid, "epoch": r}
                    )
                    bin_values[r].add(v)
                    logger.debug(
                        f"[{pid}] bin_values[{r}] is now :[{bin_values[r]}]",
                        extra={"nodeid": pid, "epoch": r}
                    )
                    bv_signal.set()
            elif tag == ABAMsgType.AUX:
                assert v in (0,1)
                if sender in aux_values[r][v]:
                    # FIXME: raise or continue? For now will raise just
                    # because it appeared first, but maybe the protocol simply
                    # needs to continue. (@sourav: copying this comment from binaryagreement)
                    print(f"[{pid}] Redundant AUX received by {sender}", msg)
                    raise RedundantMessageError("Redundant AUX received {}".format(msg))
                
                logger.debug(
                    f"[{pid}] add sender = {sender} to aux_value[{r}][{v}] = \
                        {aux_values[r][v]}",
                    extra={"nodeid": pid, "epoch": r},
                )
                aux_values[r][v].add(sender)
                logger.debug(
                    f"[{pid}] aux_values[{r}][{v}] is now: {aux_values[r][v]}",
                    extra={"nodeid": pid, "epoch": r},
                )
                bv_signal.set()
            elif tag == ABAMsgType.AUXSET:
                handle_auxset_messages(
                    sender=sender,
                    message=msg,
                    auxset_values=auxset_values,
                    pid=pid,
                    auxset_signal=auxset_signal,
                )
            elif tag == ABAMsgType.EST2:
                assert v in (0,1)
                if sender in est_values2[r][v]:
                    # FIXME: raise or continue? For now will raise just
                    # because it appeared first, but maybe the protocol simply
                    # needs to continue. (@sourav: copying this comment from binaryagreement)
                    print(f"[{pid}] Redundant EST2 received by {sender}", msg)
                    logger.warning(
                        f"[{pid}] Redundant EST2 message received by {sender}: {msg}",
                        extra={"nodeid": pid, "epoch": r},
                    )
                    raise RedundantMessageError("Redundant EST2 received {}".format(msg))
                    # continue
                
                est_values2[r][v].add(sender)
                # Relay after reaching first threshold
                if len(est_values2[r][v]) >= f+1 and not est_sent2[r][v]:
                    est_sent2[r][v] = True
                    broadcast(encode_msg(ABAMsgType.EST2,v,r))
                    logger.debug(
                        f"[{pid}] broadcast {('EST2', r, v)}",
                        extra={"nodeid":pid, "epoch": r},
                    )

                # Output after reaching second threshold
                if len(est_values2[r][v]) >= 2*f + 1:
                    logger.debug(
                        f"[{pid}] add v={v} to bin_values2[{r}] =[{bin_values2[r]}]",
                        extra={"nodeid": pid, "epoch": r}
                    )
                    bin_values2[r].add(v)
                    logger.debug(
                        f"[{pid}] bin_values2[{r}] is now :[{bin_values2[r]}]",
                        extra={"nodeid": pid, "epoch": r}
                    )
                    bv_signal.set()
            elif tag == ABAMsgType.AUX2:
                assert v in (0,1)
                if sender in aux_values2[r][v]:
                    # FIXME: raise or continue? For now will raise just
                    # because it appeared first, but maybe the protocol simply
                    # needs to continue. (@sourav: copying this comment from binaryagreement)
                    print(f"[{pid}] Redundant AUX2 received by {sender}", msg)
                    raise RedundantMessageError("Redundant AUX2 received {}".format(msg))
                
                logger.debug(
                    f"[{pid}] add sender = {sender} to aux_values2[{r}][{v}] = \
                        {aux_values2[r][v]}",
                    extra={"nodeid": pid, "epoch": r},
                )
                aux_values2[r][v].add(sender)

                logger.debug(
                    f"[{pid}] aux_values2[{r}][{v}] is now: {aux_values2[r][v]}",
                    extra={"nodeid": pid, "epoch": r},
                )
                aux_signal.set()

    _thread_recv = asyncio.create_task(_recv())

    try:
        # Block waiting for the input
        vi = await input_msg()
        assert vi in (0,1)
        est = vi
        r = 0
        already_decided = None
        while True: # Unbounded number of rounds
            logger.debug(
                f"[{pid}] Starting with est = {est}", extra={"nodeid": pid, "epoch": r}
            )

            if not est_sent[r][est]:
                est_sent[r][est] = True
                broadcast(encode_msg(ABAMsgType.EST,est,r))
            
            while len(bin_values[r]) == 0:
                # Block until a value is output
                bv_signal.clear()
                await bv_signal.wait()
            
            w = next(iter(bin_values[r])) # take an element
            logger.debug(
                f"[{pid}] broadcast {('AUX', r, w)}", 
                extra={"nodeid":pid, "epoch":r}
            )
            broadcast(encode_msg(ABAMsgType.AUX,w,r))

            values = None
            logger.debug(
                f"block until at least N-f ({n-f}) AUX values are received",
                extra={"nodeid": pid, "epoch":r},
            )

            while True:
                logger.debug(
                    f"[{pid}] bin_values[{r}]: {bin_values[r]}", 
                    extra={"nodeid": pid, "epoch":r},
                )
                logger.debug(
                    f"[{pid}] aux_values[{r}]: {aux_values[r]}", 
                    extra={"nodeid": pid, "epoch":r},
                )
                # Block until at least N-f AUX values are received
                if 1 in bin_values[r] and len(aux_values[r][1]) >= n-f:
                    values = set((1,))
                    break
                if 0 in bin_values[r] and len(aux_values[r][0]) >= n-f:
                    values = set((0,))
                    break
                if sum(len(aux_values[r][v]) for v in bin_values[r]) >= n-f:
                    values = set((0,1))
                    break
                bv_signal.clear()
                await bv_signal.wait()

            logger.debug(
                f"[{pid}] Completed AUX phase with values ={values}", 
                extra={"nodeid":pid, "epoch":r},
            )

            # X phase
            logger.debug(
                f"[{pid}] block until at least N-f ({n-f}) X values\
                are received",
                extra={"nodeid": pid, "epoch": r},
            )
            est2 = None
            if not auxset_sent[r]:
                est2 = await wait_for_auxset_values(
                    pid=pid,
                    n=n,
                    f=f,
                    epoch=r,
                    auxset_sent=auxset_sent,
                    bin_values=bin_values,
                    values=values,
                    auxset_values=auxset_values,
                    auxset_signal=auxset_signal,
                    broadcast=broadcast,
                )
            logger.debug(
                f"[{pid}] Completed AUXSET phase with values = {est2}",
                extra={"nodeid": pid, "epoch": r},
            )

            logger.debug(
                f"[{pid}] Block until receiving the common coin value",
                extra={"nodeid": pid, "epoch": r},
            )
            
            logger.debug(
                f"[{pid}] Starting SBV_Broadcast2 with est = {est2}", 
                extra={"nodeid": pid, "epoch": r}
            )

            if not est_sent2[r][est2]:
                est_sent2[r][est2] = True
                broadcast(encode_msg(ABAMsgType.EST2,est2,r))

            while len(bin_values2[r]) == 0:
                # block until a value2 is output
                bv_signal.clear()
                await bv_signal.wait()

            w = next(iter(bin_values2[r])) # take an element
            logger.debug(
                f"[{pid}] broadcast {('AUX2', r, w)}", extra={"nodeid": pid, "epoch": r}
            )
            broadcast(encode_msg(ABAMsgType.AUX2,w,r))

            values2 = None
            logger.debug(
                f"block until at least N-f ({n-f}) AUX2 values are received",
                extra={"nodeid": pid, "epoch": r},
            )

            while True:
                logger.debug(
                    f"[{pid}] bin_values2[{r}]: {bin_values2[r]}",
                    extra={"nodeid": pid, "epoch": r},
                )
                logger.debug(
                    f"[{pid}] aux_values2[{r}]: {aux_values2[r]}",
                    extra={"nodeid": pid, "epoch": r},
                )

                # Block untile at least N-f AUX2 values are received
                if 1 in bin_values2[r] and len(aux_values2[r][1]) >= n - f:
                    values2 = set((1,))
                    # print('[sid:%s] [pid:%d] VALUES 1 %d' % (sid, pid, r))
                    break
                if 0 in bin_values2[r] and len(aux_values2[r][0]) >= n - f:
                    values2 = set((0,))
                    break
                if 2 in bin_values2[r] and len(aux_values2[r][0]) >= n - f:
                    values2 = set((-1,))
                    break
                if sum(len(aux_values2[r][v]) for v in bin_values2[r]) >= n - f:
                    values2 = set(aux_values2[r][v])
                    break
                aux_signal.clear()
                await aux_signal.wait()

                logger.debug(
                    f"[{pid}] Completed AUX2 phase with values = {values2}",
                    extra={"nodeid": pid, "epoch": r},
                )

            try:
                if len(values2) == 1:
                    v = next(iter(values2))
                    if v == 2:
                        est = await _coin(r, coin_init)
                        coin_init = True
                    else:
                        if already_decided is None:
                            already_decided = v
                            decide(v)
                        elif already_decided == v:
                            # Here corresponds to a proof that if one party
                            # decides at round r, then in all the following
                            # rounds, everybody will propose r as an
                            # estimation. (Lemma 2, Lemma 1) An abandoned
                            # party is a party who has decided but no enough
                            # peers to help him end the loop.  Lemma: # of
                            # abandoned party <= t
                            raise AbandonedNodeError
                        est = v
                else:
                    v = next(iter(values2))
                    if v == 2:
                        est = next(iter(values2))
                    else:
                        est = v
                    _coin(r)
            except AbandonedNodeError:
                # print('[sid:%s] [pid:%d] QUITTING in round %d' % (sid,pid,r))
                logger.debug(f"[{pid}] QUIT!", extra={"nodeid": pid, "epoch": r})
                return
            r += 1
    finally:
        if asyncio.get_event_loop().is_running():
                _thread_recv.cancel()


async def run_binary_agreement(config, pbk, pvk, n, f, nodeid):
    from honeybadgermpc.broadcast.commoncoin import shared_coin
    import random

    sid_c = "sid_coin"
    sid_ba = "sid_ba"

    async with ProcessProgramRunner(config, n, f, nodeid) as program_runner:
        send_c, recv_c = program_runner.get_send_recv(sid_c)

        def bcast_c(o):
            for i in range(n):
                send_c(i, o)

        coin, crecv_task = await shared_coin(
            sid_c, nodeid, n, f, pbk, pvk, bcast_c, recv_c
        )

        inputq = asyncio.Queue()
        outputq = asyncio.Queue()

        send_ba, recv_ba = program_runner.get_send_recv(sid_ba)

        def bcast_ba(o):
            for i in range(n):
                send_ba(i, o)

        ba_task = tylerba(
            sid_ba,
            nodeid,
            n,
            f,
            coin,
            inputq.get,
            outputq.put_nowait,
            bcast_ba,
            recv_ba,
        )

        inputq.put_nowait(random.randint(0, 1))

        await ba_task

        logger.info("[%d] BA VALUE: %s", nodeid, await outputq.get())
        # logger.info("[%d] COIN VALUE: %s", nodeid, await coin(0))
        crecv_task.cancel()


if __name__ == "__main__":
    import pickle
    import base64
    from honeybadgermpc.config import HbmpcConfig
    from honeybadgermpc.ipc import ProcessProgramRunner
    from honeybadgermpc.broadcast.crypto.boldyreva import TBLSPublicKey  # noqa:F401
    from honeybadgermpc.broadcast.crypto.boldyreva import TBLSPrivateKey  # noqa:F401

    pbk = pickle.loads(base64.b64decode(HbmpcConfig.extras["public_key"]))
    pvk = pickle.loads(base64.b64decode(HbmpcConfig.extras["private_key"]))

    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            run_binary_agreement(
                HbmpcConfig.peers,
                pbk,
                pvk,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
            )
        )
    finally:
        loop.close()