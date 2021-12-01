import threading
import uuid
import os
import argparse
import json
import logging
import time

from aws.ec2Manager import EC2Manager
from aws.AWSConfig import AwsConfig
from aws.s3Manager import S3Manager


def get_instance_configs(instance_ips, extra={}):
    port = AwsConfig.MPC_CONFIG.PORT
    num_faulty_nodes = AwsConfig.MPC_CONFIG.NUM_FAULTY_NODES
    instance_configs = [None] * len(instance_ips)

    for my_id in range(len(instance_ips)):
        config = {
            "N": AwsConfig.MPC_CONFIG.N,
            "t": AwsConfig.MPC_CONFIG.T,
            "my_id": my_id,
            "peers": [f"{ip}:{port}" for ip in instance_ips],
            "reconstruction": {"induce_faults": False},
            "skip_preprocessing": True,
            "extra": extra,
        }

        if num_faulty_nodes > 0:
            num_faulty_nodes -= 1
            config["reconstruction"]["induce_faults"] = True
        instance_configs[my_id] = (my_id, json.dumps(config))

    return instance_configs


def run_commands_on_instances(
    ec2manager, commands_per_instance_list, verbose=True, output_file_prefix=None
):

    node_threads = [
        threading.Thread(
            target=ec2manager.execute_command_on_instance,
            args=[id, commands, verbose, output_file_prefix],
        )
        for id, commands in commands_per_instance_list
    ]

    for thread in node_threads:
        thread.start()
    for thread in node_threads:
        thread.join()

def get_adkg_setup_commands(s3manager, instance_ids):
    setup_commands = [
        [
            instance_id,
            [
                "sudo docker pull %s" % (AwsConfig.DOCKER_IMAGE_PATH),
                "mkdir -p benchmark-logs",
            ],
        ]
        for i, instance_id in enumerate(instance_ids)
    ]

    return setup_commands

# def get_drand_setup_commands(ec2manager, instance_ids):
#     commands = ec2manager.get_setup_commands()
#     print(commands)
#     setup_commands = [
#         [instance_id, commands]
#         for i, instance_id in enumerate(instance_ids)
#     ]
#     return setup_commands

def trigger_run(run_id, skip_setup, max_k, only_setup, cleanup):
    logging.info(f"Run Id: {run_id}")
    ec2manager, s3manager = EC2Manager(), S3Manager(run_id)
    instance_ids, instance_ips = ec2manager.create_instances()

    if cleanup:
        instance_commands = [
            [instance_id, ["sudo docker kill $(sudo docker ps -q); rm -rf *"]]
            for i, instance_id in enumerate(instance_ids)
        ]
        run_commands_on_instances(ec2manager, instance_commands)
        return

    port = AwsConfig.MPC_CONFIG.PORT

    if AwsConfig.MPC_CONFIG.COMMAND.endswith("adkg_run"):
        instance_configs = get_instance_configs(
            instance_ips, {"k": AwsConfig.MPC_CONFIG.K, "run_id": run_id}
        )
    elif AwsConfig.MPC_CONFIG.COMMAND.endswith("drand"):
        with open("awsips.log", "w") as ipfile:
            for ip in instance_ips:
                ipfile.write(ip+"\n")
        # setup_commands = get_drand_setup_commands(ec2manager, instance_ids)
        # logging.info("Triggering setup commands.")
        # print(setup_commands)
        # run_commands_on_instances(ec2manager, setup_commands, False)
        return
    else:
        logging.error("Application not supported to run on AWS.")
        raise SystemError

    logging.info(f"Uploading config file to S3 in '{AwsConfig.BUCKET_NAME}' bucket.")

    config_urls = s3manager.upload_configs(instance_configs)
    logging.info("Config file upload complete.")

    logging.info("Triggering config update on instances.")
    config_update_commands = [
        [instance_id, ["mkdir -p config", "cd config; curl -sSO %s" % (config_url)]]
        for config_url, instance_id in zip(config_urls, instance_ids)
    ]
    run_commands_on_instances(ec2manager, config_update_commands, False)
    logging.info("Config update completed successfully.")

    if not skip_setup:
        if AwsConfig.MPC_CONFIG.COMMAND.endswith("adkg_run"):
            setup_commands = get_adkg_setup_commands(s3manager, instance_ids)
        logging.info("Triggering setup commands.")
        run_commands_on_instances(ec2manager, setup_commands, False)

    if not only_setup:
        start_time = int(time.time()) + 30 # starting 1 minute in future
        logging.info("Setup commands executed successfully.")
        instance_commands = [
            [
                instance_id,
                [
                    f"sudo docker run\
                -p {port}:{port} \
                -v /home/ubuntu/config:/usr/src/HoneyBadgerMPC/config/ \
                -v /home/ubuntu/benchmark-logs:/usr/src/HoneyBadgerMPC/benchmark-logs/ \
                {AwsConfig.DOCKER_IMAGE_PATH} \
                {AwsConfig.MPC_CONFIG.COMMAND} -d -f config/config-{i}.json -time {start_time}"
                ],
            ]
            for i, instance_id in enumerate(instance_ids)
        ]
        logging.info("Triggering MPC commands.")
        run_commands_on_instances(ec2manager, instance_commands)
        logging.info("Collecting logs.")
        log_collection_cmds = [
            [id, ["cat benchmark-logs/*.log"]] for id in instance_ids
        ]
        os.makedirs(f"data/{run_id}", exist_ok=True)
        run_commands_on_instances(
            ec2manager, log_collection_cmds, True, f"data/{run_id}/benchmark-logs"
        )

    s3manager.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Runs ADKG code on AWS.")
    parser.add_argument(
        "-s",
        "--skip-setup",
        dest="skip_setup",
        action="store_true",
        help="If this is passed, then the setup commands are skipped.",
    )
    parser.add_argument(
        "-c",
        "--cleanup",
        dest="cleanup",
        action="store_true",
        help="This kills all running containers and deletes all stored files.",
    )
    parser.add_argument(
        "-k",
        "--max-k",
        default=AwsConfig.MPC_CONFIG.K,
        type=int,
        dest="max_k",
        help="Maximum value of k for which the inputs need to be \
        created and uploaded during the setup phase. This value is \
        ignored if --skip-setup is passed. (default: `k` in aws_config.json)",
    )
    parser.add_argument(
        "--only-setup",
        dest="only_setup",
        action="store_true",
        help="If this value is passed, then only the setup phase is run,\
         otherwise both phases are run.",
    )
    parser.add_argument(
        "--run-id",
        dest="run_id",
        nargs="?",
        help="If skip setup is passed, then a previous run_id for the same\
        MPC application needs to be specified to pickup the correct input files.",
    )
    args = parser.parse_args()
    if args.skip_setup and args.only_setup:
        parser.error("--only-setup and --skip-setup are mutually exclusive.")
    if args.skip_setup and not args.run_id:
        parser.error("--run-id needs to be passed with --skip-setup.")
    args.run_id = uuid.uuid4().hex if args.run_id is None else args.run_id
    trigger_run(args.run_id, args.skip_setup, args.max_k, args.only_setup, args.cleanup)
