from adkg.config import HbmpcConfig
from adkg.ipc import ProcessProgramRunner
from adkg.adkg import ADKG
from adkg.poly_commit_feldman import PolyCommitFeldman
from pypairing import G1, ZR
import asyncio
import time
import logging
import uvloop

logger = logging.getLogger("benchmark_logger")
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

# def get_avss_params(n):
#     g, h = G1.hash(b'g'), G1.rand(b'h')   
#     public_keys, private_keys = [None] * n, [None] * n
#     for i in range(n):
#         private_keys[i] = ZR.hash(bytes(i))
#         public_keys[i] = pow(g, private_keys[i])
#     return g, h, public_keys, private_keys

def get_avss_params(n):
    from pypairing import G1
    from phe import PaillierPublicKey, PaillierPrivateKey
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    g, h = G1.hash(b'g'), G1.hash(b'h') 

    public_keys = [None for _ in range(n)]
    private_keys = [None for _ in range(n)]
    with open("apps/tutorial/keys", 'r') as kfile:
        keys = kfile.readlines()
        for i in range(n):
            data = keys[i].split(' ')
            public_keys[i] = PaillierPublicKey(int(data[0]))
            private_keys[i] = PaillierPrivateKey(public_keys[i], int(data[1]), int(data[2]))
    return g, h, public_keys, private_keys

async def _run(peers, n, t, my_id, start_time):
    g, h, pks, sks = get_avss_params(n)
    pc = PolyCommitFeldman(g)
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("")
        logging.debug(f"Starting ADKG: {(my_id)}")
        logging.debug(f"Start time: {(start_time)}, diff {(start_time-int(time.time()))}")

        benchmark_logger = logging.LoggerAdapter(
           logging.getLogger("benchmark_logger"), {"node_id": my_id}
        )

        deg = 2*t
        with ADKG(pks, sks[my_id], g, h, n, t, deg, my_id, send, recv, pc) as adkg:
            while True:
                if time.time() > start_time:
                    break
                time.sleep(0.1)
            begin_time = time.time()
            logging.info(f"ADKG start time: {(begin_time)}")
            adkg_task = asyncio.create_task(adkg.run_adkg(begin_time))
            logging.debug(f"Created ADKG task, now waiting...")
            await adkg_task
            end_time = time.time()
            adkg_time = end_time-begin_time
            logging.info(f"ADKG time: {(adkg_time)}")
            benchmark_logger.info("ADKG time: %f", adkg_time)
            adkg.kill()
            adkg_task.cancel()
        bytes_sent = runner.node_communicator.bytes_sent
        for k,v in runner.node_communicator.bytes_count.items():
            logging.info(f"[{my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logging.info(f"[{my_id}] Total bytes sent out aa: {bytes_sent}")

if __name__ == "__main__":
    from adkg.config import HbmpcConfig
    logging.info("Running ADKG ...")
    HbmpcConfig.load_config()

    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
                HbmpcConfig.time,
            )
        )
    finally:
        loop.close()
