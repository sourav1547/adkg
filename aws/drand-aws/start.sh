cd drand

IP=$1
LeaderAddr=$2
N=${3:-"4"}
T=$(( $N/2 + 1 ))
isLeader=${4:-"no"}

killall drand
# rm -rf datadir

IPpriv=`ip address show | \
    grep "inet .* brd" | \
    sed 's/ brd.*//g' | \
    sed 's/inet //' | \
    sed 's;/.*;;g' | \
    sed 's/.* //g'`

# ./drand generate-keypair --tls-disable --folder datadir $IP:7080

echo "mysecret901234567890123456789012" > secret-file.log

./drand start --folder datadir --tls-disable --private-listen 0.0.0.0:7090 --control 0.0.0.0:7088 &

sleep 60

if [ $isLeader == "no" ] ; then
    sleep 30
    echo "Connecting to $LeaderAddr"
    ./drand --folder datadir share --tls-disable --connect $LeaderAddr --nodes $N --threshold $T --secret-file secret-file.log --timeout "90s" --period "15s"  --control 0.0.0.0:7088
else 
    ./drand --folder datadir share --tls-disable --leader --nodes $N --threshold $T --secret-file secret-file.log --timeout "90s" --period "15s"  --control 0.0.0.0:7088
fi

# sleep 300
# killall drand