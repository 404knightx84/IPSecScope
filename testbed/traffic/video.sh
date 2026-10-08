#!/bin/bash
# usage: video.sh DURATION SEED  (player-like: one 2-second segment every ~2 s)
DUR=${1:-60}; RANDOM=${2:-1}
QS=(low high); Q=${QS[$((RANDOM % 2))]}
N=0; END=$((SECONDS+DUR))
while [ $SECONDS -lt $END ]; do
  docker exec gw-a curl -s -o /dev/null --max-time 10 http://10.0.0.3:8080/video/${Q}_$(printf %03d $((N % 30))).ts
  N=$((N+1))
  sleep 1.7
done
