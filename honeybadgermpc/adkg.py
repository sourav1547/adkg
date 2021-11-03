from inspect import CO_NESTED
from honeybadgermpc.broadcast.reliablebroadcast import reliablebroadcast
from honeybadgermpc.acss import Hbacss0SingleShare
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.share_recovery import interpolate_g1_at_x
from pypairing import G1, ZR
from honeybadgermpc.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib
from honeybadgermpc.broadcast.crypto.boldyreva import TBLSPublicKey  # noqa:F401
from honeybadgermpc.broadcast.crypto.boldyreva import TBLSPrivateKey  # noqa:F401

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
    
    def kill(self):
        self.subscribe_recv_task.cancel()
        for task in self.acss_tasks:
            task.cancel()
        self.acss.kill()
        self.acss_task.cancel()
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, outputs, value, acss_signal):
        #todo, need to modify send and recv
        # Need different send and recv instances for different component of the code.
        acsstag = "ACSS"
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
                if len(outputs) >= self.n - self.t:
                    print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
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
            rbc_values[j] = await rbc_out[j]

            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            while True:
                for k in rbc_values[j]:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    skj = 0
                    coeffs = [G1.identity() for _ in range(self.t+1)]
                    for kk in rbc_values[j]:
                        skj = skj + acss_outputs[kk][0][0]
                        commitments = acss_outputs[kk][1]
                        for i in range(len(coeffs)):
                            coeffs[i] = coeffs[i]*commitments[0][i] #TODO: Optimize this
                    
                    pkj = [G1.identity() for _ in range(self.n)] #TODO: Optimize this
                    for i in range(self.n):
                        exp = ZR(1)
                        pkji = G1.identity()
                        for j in range(len(coeffs)):
                            pkji*=coeffs[j]**exp
                            exp *= (i+1)
                        pkj[i] = pkji
                    bpk = TBLSPublicKey(self.n, self.t, pkj[j], pkj)
                    bsk = TBLSPrivateKey(self.n, self.t, pkj[j], pkj, skj, j)
                    coin_keys[j]((bpk, bsk))
                    acss_signal.clear()
                    return 
                acss_signal.clear()
                await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]

        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block
            # print pid, j, 'ENTERING CRITICAL'
            if sum(aba_values) >= self.n - self.t:
                # Provide 0 to all other aba
                for k in range(self.n):
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)
        
        await asyncio.gather(*[asyncio.create_task(_recv_aba(j)) for j in range(self.n)])
        assert sum(aba_values) >= self.n - self.t  # Must have at least N-f committed

        # Wait for the corresponding broadcasts
        for j in range(self.n):
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                rbc_values[j] = None

        rbc_signal.set()
        return 

    async def agreement(self, key_proposal, acss_outputs, acss_signal):
        from honeybadgermpc.broadcast.tylerba import tylerba
        from honeybadgermpc.broadcast.qrbc import qrbc

        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_key_proposal):
            if len(_key_proposal) < self.n -self.t:
                return False
        
            while True:
                subset = True
                for k in _key_proposal:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    acss_signal.clear()    
                    return True
                acss_signal.clear()
                await acss_signal.wait()

        async def _setup(j):
            abatag = "ABA" + str(j)
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

            # Only leader gets input
            rbc_input = bytes(key_proposal) if j == self.my_id else None

            rbctag ="RBC" + str(j)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)
            
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
        for k in mks:
            secret = secret + acss_outputs[k][0][0]
        
        x = self.g**secret
        y = self.h**secret
        cp = CP(self.g, self.h)
        chal, res = cp.dleq_prove(secret, x, y)

        key_tag = "ACS_KEY"
        send, recv = self.get_send(key_tag), self.subscribe_recv(key_tag)

        print("Node " + str(self.my_id) + " starting key-derivation")
        for i in range(self.n):
            send(i, (x, y, chal, res))

        pk_shares = []
        while True:
            (sender, msg) = await recv()
            x, y, chal, res = msg
            if cp.dleq_verify(x, y, chal, res):
                pk_shares.append([sender+1, y])
                print("Node " + str(self.my_id) + "Received key shares from "+ str(sender))
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

    async def run_adkg(self):
        acss_outputs = {}
        acss_signal = asyncio.Event()

        value =[ZR.rand()]
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, value, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        key_proposal = list(acss_outputs.keys())
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, acss_outputs, acss_signal))
        acs, key_task, work_tasks = await create_acs_task
        await asyncio.gather(acs)
        await asyncio.gather(*work_tasks)
        output = await key_task
        mks, sk, pk = output
        self.output_queue.put_nowait((value[0], mks, sk, pk))