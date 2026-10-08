#!/bin/bash
# usage: ping.sh DURATION SEED   (ICMP, varied sizes 8-1300 bytes)
DUR=${1:-60}; RANDOM=${2:-1}
END=$((SECONDS+DUR))
while [ $SECONDS -lt $END ]; do
  SIZE=$((8 + RANDOM % 1293))
  docker exec gw-a ping -c 1 -W 1 -s $SIZE 10.0.0.3 >/dev/null 2>&1
  sleep 0.$((2 + RANDOM % 8))
done
