from honeybadgermpc.config import HbmpcConfig
from honeybadgermpc.ipc import ProcessProgramRunner
from honeybadgermpc.adkg import ADKG
# from honeybadgermpc.poly_commit_feldman import PolyCommitFeldman
from honeybadgermpc.poly_commit_bulletproof_blind import PolyCommitBulletproofBlind
from honeybadgermpc.poly_commit_hybrid import PolyCommitHybrid
from pypairing import G1, ZR
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1
import asyncio
import time
import logging
import uvloop

logger = logging.getLogger("benchmark_logger")
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

def get_avss_params(n, t):
    gs = G1.hash_many(b"honeybadgerg", 2*t+1)
    hs = G1.hash(b"honeybadgerh")
    u = G1.hash(b"honeybadgeru")
    crs = [gs, hs, u]
    g, h = gs[0], G1.hash(b'h')   
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.hash(bytes(i))
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys, crs

async def _run(peers, n, t, my_id, start_time):
    g, h, pks, sks, crs = get_avss_params(n, t)
    # pc = PolyCommitFeldman(g, group=G1)
    pc = PolyCommitBulletproofBlind(crs, 2*t, group=G1)
    pc2 = PolyCommitHybrid(crs, 2*t, group=G1)
    
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("A")
        logging.debug(f"Starting ADKG: {(my_id)}")
        logging.debug(f"Start time: {(start_time)}, diff {(start_time-int(time.time()))}")

        benchmark_logger = logging.LoggerAdapter(
           logging.getLogger("benchmark_logger"), {"node_id": my_id}
        )

        with ADKG(pks, sks[my_id], g, h, n, t, my_id, send, recv, pc, pc2) as adkg:
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
    from honeybadgermpc.config import HbmpcConfig
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
