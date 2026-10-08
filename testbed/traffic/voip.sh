#!/bin/bash
# usage: voip.sh DURATION SEED
docker exec gw-a python3 /tmp/voip.py send ${1:-60} ${2:-1}
