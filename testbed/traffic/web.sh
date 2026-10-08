#!/bin/bash
# usage: web.sh DURATION SEED   (curl to a web server on gw-b, files of varied size)
DUR=${1:-60}; RANDOM=${2:-1}
FILES=(1k 5k 20k 100k 500k 1m)
END=$((SECONDS+DUR))
while [ $SECONDS -lt $END ]; do
  F=${FILES[$((RANDOM % 6))]}
  docker exec gw-a curl -s -o /dev/null --max-time 10 http://10.0.0.3:8080/$F.bin
  sleep 0.$((1 + RANDOM % 9))
done
