from inspect import CO_NESTED
from adkg.broadcast.reliablebroadcast import reliablebroadcast
from adkg.acss import Hbacss0SingleShare
from adkg.polynomial import polynomials_over
from adkg.share_recovery import interpolate_g1_at_x
from pypairing import G1, ZR
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib
import time
import logging
from adkg.utils.serilization import serialize_g, deserialize_g, serialize_f, deserialize_f
from adkg.utils.bitmap import Bitmap

from adkg.acss_dcr import ACSS_DCR
# import phe

class ADKGMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    KEY = "K"
    
class CP:
    def __init__(self, g, h, field=ZR):
        self.g  = g
        self.h = h

    def dleq_derive_chal(self, x, y, a1, a2):
        commit = str(x)+str(y)+str(a1)+str(a2)
        try:
            commit = commit.encode()
        except AttributeError:
            pass 
        # TODO: Convert the hash output to a field element.
        hs =  hashlib.sha256(commit).digest() 
        return ZR.hash(hs)

    def dleq_verify(self, x, y, chal, res):
        a1 = (x**chal)*(self.g**res)
        a2 = (y**chal)*(self.h**res)
        eLocal = self.dleq_derive_chal(x, a1, y, a2)
        if eLocal == chal:
            return True
        return False

    def dleq_prove(self, alpha, x, y):
        w = ZR.random()
        a1 = self.g**w
        a2 = self.h**w
        e = self.dleq_derive_chal(x, a1, y, a2)
        return  e, w - e*alpha # return (challenge, response)

class ADKG:
    def __init__(self, public_keys, private_key, g, h, n, t, my_id, send, recv, pc, field=ZR):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.my_id = (n, t, my_id)
        self.send, self.recv, self.pc, self.field = (send, recv, pc, field)
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()


        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )
            
    def kill(self):
        self.benchmark_logger.info("ADKG kill called")
        self.subscribe_recv_task.cancel()
        self.benchmark_logger.info("ADKG Recv task canceled called")
        for task in self.acss_tasks:
            task.cancel()
        self.benchmark_logger.info("ADKG ACSS tasks canceled")
        # TODO: To determine the order of kills, I think that might giving that error.
        # 1. 
        self.acss.kill()
        self.benchmark_logger.info("ADKG ACSS killed")
        self.acss_task.cancel()
        self.benchmark_logger.info("ADKG ACSS task killed")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, outputs, value, acss_signal):
        #todo, need to modify send and recv
        # Need different send and recv instances for different component of the code.
        acsstag = ADKGMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        # self.acss = Hbacss0SingleShare(self.public_keys, self.private_key, self.g, self.n, self.t, self.my_id, acsssend, acssrecv, self.pc)

        self.acss = ACSS_DCR(self.public_keys, self.private_key, self.g, self.n, self.t, self.my_id, acsssend, acssrecv)

        self.acss_tasks = [None] * self.n
        # value =[ZR.rand()]
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, values=value))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, dealer_id=i))

        while True:
                (dealer, _, share, commitments) = await self.acss.output_queue.get()
                outputs[dealer] = [share, commitments]
                # if len(outputs) >= self.n - self.t:
                if len(outputs) > self.t:
                    # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                    acss_signal.set()

                if len(outputs) == self.n:
                    return    

    async def commonsubset(self, rbc_out, acss_outputs, acss_signal, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            # rbc_values[j] = await rbc_out[j]
            rbcl = await rbc_out[j].get()
            rbcb = Bitmap(self.n, rbcl)
            rbc_values[j] = []
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
                    
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            while True:
                acss_signal.clear()
                for k in rbc_values[j]:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    coin_keys[j]((acss_outputs, rbc_values[j]))
                    return
                await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]

        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block
            # print pid, j, 'ENTERING CRITICAL'
            # if sum(aba_values) >= self.n - self.t:
            if sum(aba_values) >= 1:
                # Provide 0 to all other aba
                for k in range(self.n):
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)
        
        await asyncio.gather(*[asyncio.create_task(_recv_aba(j)) for j in range(self.n)])
        # assert sum(aba_values) >= self.n - self.t  # Must have at least N-f committed
        assert sum(aba_values) >= 1  # Must have at least N-f committed

        # Wait for the corresponding broadcasts
        for j in range(self.n):
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                rbc_values[j] = None

        rbc_signal.set()

    async def agreement(self, key_proposal, acss_outputs, acss_signal):
        from adkg.broadcast.tylerba import tylerba
        # from adkg.broadcast.qrbc import qrbc
        from adkg.broadcast.optqrbc import optqrbc

        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_key_proposal):
            kp = Bitmap(self.n, _key_proposal)
            kpl = []
            for ii in range(self.n):
                if kp.get_bit(ii):
                    kpl.append(ii)
            if len(kpl) <= self.t:
                return False
        
            while True:
                subset = True
                for kk in kpl:
                    if kk not in acss_outputs.keys():
                        subset = False
                if subset:
                    acss_signal.clear()    
                    return True
                acss_signal.clear()
                await acss_signal.wait()

        async def _setup(j):
            
            # starting RBC
            rbctag =ADKGMsgType.RBC + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)

            # rbc_outputs[j] = 
            asyncio.create_task(
                optqrbc(
                    rbctag,
                    self.my_id,
                    self.n,
                    self.t,
                    j,
                    predicate,
                    rbc_input,
                    rbc_outputs[j].put_nowait,
                    rbcsend,
                    rbcrecv,
                )
            )

            abatag = ADKGMsgType.ABA + str(j) # (B, msg)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(self.n):
                    abasend(i, o)
                
            aba_task = asyncio.create_task(
                tylerba(
                    abatag,
                    self.my_id,
                    self.n,
                    self.t,
                    coin_keys[j].get,
                    aba_inputs[j].get,
                    aba_outputs[j].put_nowait,
                    bcast,
                    abarecv,
                )
            )
            return aba_task

        work_tasks = await asyncio.gather(*[_setup(j) for j in range(self.n)])
        rbc_signal = asyncio.Event()
        rbc_values = [None for i in range(self.n)]

        return (
            self.commonsubset(
                rbc_outputs,
                acss_outputs,
                acss_signal,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.derive_key(
                acss_outputs,
                acss_signal,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def derive_key(self, acss_outputs, acss_signal, rbc_values, rbc_signal):
        # Waiting for the ABA to terminate
        await rbc_signal.wait()
        rbc_signal.clear()

        mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                mks = mks.union(set(list(ks)))

        for k in mks:
            if k not in acss_outputs:
                await acss_signal.wait()
                acss_signal.clear()
        
        secret = 0
        # coeffs = [G1.identity() for _ in range(self.t+1)]
        for k in mks:
            secret = secret + acss_outputs[k][0][0]
            # Computing aggregated coeffients
            # for i in range(self.t+1):
                # coeffs[i] = coeffs[i]*acss_outputs[k][1][0][i]
        
        x = self.g**secret
        y = self.h**secret
        cp = CP(self.g, self.h)
        chal, res = cp.dleq_prove(secret, x, y)

        keytag = ADKGMsgType.KEY
        send, recv = self.get_send(keytag), self.subscribe_recv(keytag)

        # print("Node " + str(self.my_id) + " starting key-derivation")
        # yb, chalb, resb = serialize_g(y), serialize_f(chal), serialize_f(res)
        xb, yb, chalb, resb = serialize_g(x), serialize_g(y), serialize_f(chal), serialize_f(res)
        for i in range(self.n):
            send(i, (xb, yb, chalb, resb))

        pk_shares = []
        while True:
            (sender, msg) = await recv()
            xb, yb, chalb, resb = msg
            x, y, chal, res =  deserialize_g(xb), deserialize_g(yb), deserialize_f(chalb), deserialize_f(resb)

            # polynomial evaluation, not optimized
            # x = G1.identity()
            # exp = ZR(1)
            # for j in range(self.t+1):
            #     x *= coeffs[j]**exp
            #     exp *= (sender+1)
        
            
            if cp.dleq_verify(x, y, chal, res):
                pk_shares.append([sender+1, y])
                # print("Node " + str(self.my_id) + " received key shares from "+ str(sender))
            if len(pk_shares) > self.t:
                break
        pk =  interpolate_g1_at_x(pk_shares, 0)
        return (mks, secret, pk)

    # TODO: This function given an index computes g^x
    def derive_x(self, acss_outputs, mks):
        xlist = []
        for i in range(self.n):
            xi = G1.identity()
            for ii in mks:
                # TODO: This is not the correct implementation.
                xi = xi*acss_outputs[ii][i]
            xlist.append(xi)
        return xlist

    async def run_adkg(self, start_time):
        acss_outputs = {}
        acss_signal = asyncio.Event()

        acss_start_time = time.time()
        value =[ZR.rand()]
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, value, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        acss_time = time.time() - acss_start_time
        logging.info(f"ACSS time: {(acss_time)}")
        key_proposal = list(acss_outputs.keys())
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, acss_outputs, acss_signal))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        adkg_time = time.time()-start_time
        self.benchmark_logger.info("ADKG time2: %f", adkg_time)
        logging.info(f"ADKG time: {(adkg_time)}")
        await asyncio.gather(*work_tasks)
        mks, sk, pk = output
        self.output_queue.put_nowait((value[0], mks, sk, pk))