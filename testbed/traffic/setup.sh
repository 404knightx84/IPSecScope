#!/bin/bash
# copies helpers into the gateways, makes web files, starts the servers on gw-b
cd ~/ipsecscope/testbed/traffic || exit 1
docker cp voip.py gw-a:/tmp/voip.py
docker cp voip.py gw-b:/tmp/voip.py
docker exec gw-b bash -c 'mkdir -p /srv/www && cd /srv/www && for s in 1k 5k 20k 100k 500k 1m; do [ -f $s.bin ] || head -c $s /dev/urandom > $s.bin; done'
docker exec -d gw-b python3 -m http.server 8080 --directory /srv/www
docker exec -d gw-b python3 /tmp/voip.py echo
echo "traffic servers started on gw-b"
