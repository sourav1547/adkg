#!/bin/bash
set -e  # fail if any command fails

# This script runs an MPC program in N processes.
# Usage: scripts/launch-tmuxlocal.sh honeybadgermpc/ipc.py conf/mpc/local

if [ $# -lt 2 ] ; then
    echo "usage: $0 <module.py> <conf>"
    echo "example: $0 honeybadgermpc/ipc.py conf/mpc/local"
    exit 1
fi

if [ -z "$1" ]
  then
    echo "MPC file to run not specified."
fi

if [ -z "$2" ]
  then
    echo "MPC config file prefix not specified."
fi

# Change dir/file.py to dir.file
FILE_PATH=$1
DIRS=(${FILE_PATH//\// })
DOT_SEPARATED_PATH=$(IFS=. ; echo "${DIRS[*]}")
# MODULE_PATH=${DOT_SEPARATED_PATH: : -3}
MODULE_PATH=${DOT_SEPARATED_PATH%???}

CONFIG_PATH=$2

CMD="python3 -m ${MODULE_PATH}"
echo ">>> Command to be executed: '${CMD}'"

# Create simulated latency using tc
# sudo sh scripts/latency-control.sh stop
# sudo sh scripts/latency-control.sh start 50ms 10ms

start_time=$(date +%s)
start_time=$((start_time+10))

## TODO: the following was used for launching a larger number
## of processes locally, with only a portion of them shown in tmux
for ID in $(seq 4 13)
do
   echo
   ${CMD} -d -f ${CONFIG_PATH}.${ID}.json -time $start_time > logs/logs-${ID}.log 2>&1 &
done

# sleep 3s
if [ -z "$3" ]
  then
    set -x
    rm -rf sharedata/
    tmux new-session     "${CMD} -d -f ${CONFIG_PATH}.0.json -time $start_time; sh" \; \
        splitw -h -p 50 "${CMD} -d -f ${CONFIG_PATH}.1.json -time $start_time; sh" \; \
        splitw -v -p 66 "${CMD} -d -f ${CONFIG_PATH}.2.json -time $start_time; sh" \; \
        splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.3.json -time $start_time; sh" \; \
        # selectp -t 0 \; \
        # splitw -v -p 66 "${CMD} -d -f ${CONFIG_PATH}.4.json; sh" \; \
        # splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.5.json; sh"


elif [ "$3" == "dealer" ]
  then
    set -x
    rm -rf sharedata/
    tmux new-session     "${CMD} -d -f ${CONFIG_PATH}.0.json > xxxxxxxx.out; sh" \; \
        splitw -h -p 50 "${CMD} -d -f ${CONFIG_PATH}.1.json; sh" \; \
        splitw -v -p 50 "sleep 2; ${CMD} -d -f ${CONFIG_PATH}.2.json; sh" \; \
        selectp -t 0 \; \
        splitw -v -p 50 "sleep 4; ${CMD} -d -f ${CONFIG_PATH}.3.json; sh" \; \
        splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.4.json; sh"
fi
