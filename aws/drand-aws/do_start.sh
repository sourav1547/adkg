# Do the setup on the AWS Server

FILE="${1:-/dev/stdin}"
IPS=()

while IFS= read -r line; do
  IPS+=($line)
done < $FILE

N=${#IPS[@]}
Nm1=$(( $N - 1 ))

LeaderAddr=${IPS[$Nm1]}

for((i=0;i<$N;i++))
do
    ip=${IPS[$i]}
    if [ $i == $Nm1 ]; then
        ssh -i $node ubuntu@$ip 'timeout 2000 bash -ls --' < ./aws/drand-aws/start.sh $ip "$LeaderAddr:7090" $N "leader" &
    else
        ssh -i $node ubuntu@$ip 'timeout 2000 bash -ls --' < ./aws/drand-aws/start.sh $ip "$LeaderAddr:7090" $N &
    fi
done

wait