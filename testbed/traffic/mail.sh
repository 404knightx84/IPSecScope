#!/bin/bash
# usage: mail.sh DURATION SEED
docker exec gw-a python3 /tmp/mail.py send ${1:-60} ${2:-1}
