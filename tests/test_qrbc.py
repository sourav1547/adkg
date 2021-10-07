from benchmark.test_benchmark_rbc import rbc
from honeybadgermpc.broadcast.qrbc import qrbc
from random import randint
from pytest import mark
from asyncio import create_task, gather
from asyncio import Queue, Event
import os

@mark.asyncio
async def test_rbc(test_router):
    n, t = 4, 1
    msglen = 10*(t+1)
    sends, recvs, _ = test_router(n)
    dealer_id = randint(0, n-1)
    msg = os.urandom(msglen)

    sid = "sidA"

    async def predicate(m=None):
        return True 

    rbc_tasks = [None]*n

    for i in range(n):
        rbc_tasks[i] = create_task(
            qrbc(
                sid, 
                i, 
                n, 
                t, 
                dealer_id, 
                predicate,
                msg,
                sends[i], 
                recvs[i],
            )
        )

    outs = await gather(*rbc_tasks)
    assert len(set(outs)) == 1
    for task in rbc_tasks:
        task.cancel()
    

