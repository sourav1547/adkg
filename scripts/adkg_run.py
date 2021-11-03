from honeybadgermpc.config import HbmpcConfig
from honeybadgermpc.ipc import ProcessProgramRunner
from honeybadgermpc.adkg import ADKG
from honeybadgermpc.poly_commit_feldman import PolyCommitFeldman
from pypairing import G1, ZR
import asyncio
import time
import logging

logger = logging.getLogger("benchmark_logger")
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

def get_avss_params(n, t):
    g, h = G1.hash(b'g'), G1.rand(b'h')   
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random([0, 0, 0, i])
        # private_keys[i] = ZR.hash(i) # TODO: Convert i to byte string
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys

async def _run(peers, n, t, my_id):
    g, h, pks, sks = get_avss_params(n + 1, t)
    pc = PolyCommitFeldman(g)
    # Q: What is ProcessProgramRunner?
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("ADKG")
        logging.info(f"Starting ADKG: {(my_id)}")

        with ADKG(pks, sks[my_id], g, h, n, t, my_id, send, recv, pc) as adkg:
            begin_time = time.time()
            logging.info(f"ADKG start time: {(begin_time)}")
            adkg_task = asyncio.create_task(adkg.run_adkg())
            # await adkg.output_queue.get()
            logging.info(f"Created ADKG task, now waiting...")
            await adkg_task
            end_time = time.time()
            logging.info(f"ADKG time: {(end_time - begin_time)}")
            print("ADKG time:", str(end_time - begin_time))
            adkg.kill()
            adkg_task.cancel()

if __name__ == "__main__":
    from honeybadgermpc.config import HbmpcConfig
    logging.info("Running ADKG ...")
    HbmpcConfig.load_config()

    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    
    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
            )
        )
    finally:
        loop.close()
