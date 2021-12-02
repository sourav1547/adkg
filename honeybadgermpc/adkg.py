from inspect import CO_NESTED
from honeybadgermpc.acss import Hbacss0SingleShare
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.share_recovery import interpolate_g1_at_x
from honeybadgermpc.utils.serilization import deserialize_g, deserialize_gs, serialize_f, serialize_g
# from pypairing import G1, ZR
from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp
from honeybadgermpc.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib
import time
import logging
from honeybadgermpc.utils.serilization import serialize_g, deserialize_g, serialize_f, deserialize_f
from honeybadgermpc.utils.bitmap import Bitmap
from pickle import dumps


class CP:
    def __init__(self, g, h, field=ZR):
        self.g  = g
        self.h = h

    def dleq_derive_chal(self, x, y, a1, a2):
        hs = ZR.hash(hashlib.sha256(dumps((x,y,a1,a2))).digest())
        return  hs

    def dleq_verify(self, x, y, chal, res):
        a1 = multiexp([x, self.g], [chal, res])
        a2 = multiexp([y, self.h], [chal, res])
        valid = chal == self.dleq_derive_chal(x, a1, y, a2)
        return valid
        
    def dleq_prove(self, alpha, x, y):
        w = ZR.random()
        a1 = self.g.pow(w)
        a2 = self.h.pow(w)
        e = self.dleq_derive_chal(x, a1, y, a2)
        resp = w - e*alpha
        return  e, resp  # return (challenge, response)

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
        acsstag = "A"
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = Hbacss0SingleShare(self.public_keys, self.private_key, self.g, self.n, self.t, self.my_id, acsssend, acssrecv, self.pc)
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
            rbcl = await rbc_out[j]
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
        from honeybadgermpc.broadcast.tylerba import tylerba
        from honeybadgermpc.broadcast.qrbc import qrbc
        from honeybadgermpc.broadcast.optqrbc import optqrbc

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
            rbctag ="R" + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)

            rbc_outputs[j] = asyncio.create_task(
                qrbc(
                    rbctag,
                    self.my_id,
                    self.n,
                    self.t,
                    j,
                    predicate,
                    rbc_input,
                    rbcsend,
                    rbcrecv,
                )
            )

            abatag = "B" + str(j) # (B, msg)
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
        
        secret = ZR(0)
        for k in mks:
            secret = secret + acss_outputs[k][0][0]
        
        x = self.g.pow(secret)
        y = self.h.pow(secret)
        cp = CP(self.g, self.h)
        chal, res = cp.dleq_prove(secret, x, y)

        key_tag = "K" # (K, msg)
        send, recv = self.get_send(key_tag), self.subscribe_recv(key_tag)

        # print("Node " + str(self.my_id) + " starting key-derivation")
        xb, yb = serialize_g(x), serialize_g(y)
        chalb, resb = serialize_f(chal), serialize_f(res)
        for i in range(self.n):
            send(i, (xb, yb, chalb, resb))

        pk_shares = []
        while True:
            (sender, msg) = await recv()
            xb, yb, chalb, resb = msg
            x, y = deserialize_g(xb), deserialize_g(yb)
            chal, res = deserialize_f(chalb), deserialize_f(resb)
            
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