from collections import defaultdict
from honeybadgermpc.broadcast.reliablebroadcast import reliablebroadcast
from honeybadgermpc.acss import Hbacss0SingleShare
from pypairing import ZR
from honeybadgermpc.utils.misc import wrap_send, subscribe_recv
import asyncio

class adkg:
    def __init__(self, public_keys, private_key, g, h, n, t, my_id, send, recv, pc, field=ZR):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.my_id = (n, t, my_id)
        self.send, self.recv, self.pc, self.field = (send, recv, pc, field)
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()
    
    def kill(self):
        for task in self.acss_tasks:
            task.cancel()
        self.acss.kill()
        self.subscribe_recv_task.cancel()

    async def acss_step(self, outputs, acss_signal):
        #todo, need to modify send and recv
        # Need different send and recv instances for different component of the code.
        acsstag = "ACSS"
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = Hbacss0SingleShare(self.public_keys, self.private_key, self.g, self.n, self.t, self.my_id, acsssend, acssrecv, self.pc)
        self.acss_tasks = [None] * self.n
        value =[ZR.rand()]
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, values=value))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, dealer_id=i))

        while True:
                (dealer, _, share) = await self.acss.output_queue.get()
                outputs[dealer] = share
                print("appended")
                
                if len(outputs) >= self.n - self.t:
                    print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                    acss_signal.set()

                if len(outputs) == self.n:
                    self.output_queue.put_nowait("DONE")
                    return    

    async def key_proposal_step(self, key_proposal, acss_outputs, rbc_outputs,acss_signal, rbc_signal):
        
        async def predicate(_key_proposal):
            if len(_key_proposal) < self.n -self.t:
                return False
            
            while True:
                not_subset = True
                for k in _key_proposal:
                    if k not in acss_outputs.keys():
                        not_subset = False
                if not not_subset:
                    acss_signal.clear()
                    return True
                await acss_signal.wait()
                

        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(qrbc(, key_proposal, None,))
            else:
                self.acss_tasks[i] = asyncio.create_task(qrbc(0, None, predicate, dealer_id=i))

        while True:
            output = await self.qrbc.output_queue.get()
            rbc_outputs.append(output)
            rbc_signal.set()
            print("appended")
            
            if len(rbc_outputs) == n:
                return


    # async def aba_step(self, rbc_outputs, rbc_signal, acs_signal):
    #     aba_outputs = [-1]*self.n
    #     aba_started = [False]*self.n
    #     inputs = Queue()

    #     if idx in range(n):
    #         aba(i, inputs[i], other parameters)

        

    #     while True:
    #         idx = rbc_signal.wait()
    #         rbc_signal.clear()
    #         inputs[idx] = 1

    #     asyncio.gather()
    #     acs_signal.set()

    async def run_adkg(self):
        acss_outputs = {}
        rbc_outputs = defaultdict(lambda:[])
        aba_outputs = []
        acss_signal = asyncio.Event()
        rbc_signal = asyncio.Event()
        acs_signal = asyncio.Event()

        asyncio.create_task(self.acss_step(acss_outputs, acss_signal))
        await acss_signal.wait()

        key_proposal = list(acss_outputs.keys()) # @sourav: checked so far
        asyncio.create_task(self.key_proposal_step(key_proposal, acss_outputs, rbc_outputs, acss_signal, rbc_signal))
        # await asyncio.create_task(self.commonsubset(rbc_outputs, rbc_signal, aba_outputs, _signal))

        # master_key_set = set()
        # while True:
            # 1. Wait till all RBC corresponding to ABA[i]=1 terminates
            # 2. Use rbc_signal for this
            # 3. Take Union
        
        # while True:
            # 1. All ACSS in the master_key_set output
            # 2. Use acss_signal for this

        # Add all acss shares in master key set z = Sum(z_i)
        # Send <KEY, h^z_i, pi_i> to all
        # Waits for \ths valid KEY messages
        # Interpolate to compute h^z