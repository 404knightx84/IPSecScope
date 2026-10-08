#!/bin/bash
cd ~/ipsecscope/testbed || exit 1
sudo -v
docker-compose up -d
for g in gw-a gw-b; do
  docker exec $g sh -c 'grep -q i_dont_care /etc/strongswan.conf || printf "\ncharon {\n  i_dont_care_about_security_and_use_aggressive_mode_psk = yes\n}\n" >> /etc/strongswan.conf'
done
for g in gw-a gw-b; do
  docker exec $g swanctl --stats >/dev/null 2>&1 || { docker exec $g rm -f /var/run/charon.vici /var/run/charon.pid /var/run/charon.ctl; docker exec -d $g /usr/lib/ipsec/charon; }
done
sleep 3
docker exec host-a ip route replace default via 10.0.1.2
docker exec host-b ip route replace default via 10.0.2.2
for c in gw-a gw-b host-a host-b; do
  for i in $(docker exec $c ls /sys/class/net | grep eth); do
    docker exec $c ethtool -K $i gro off gso off tso off lro off >/dev/null 2>&1
  done
done
BR=br-$(docker network inspect testbed_wan -f '{{.Id}}' | cut -c1-12)
sudo ethtool -K $BR gro off gso off tso off lro off >/dev/null 2>&1
for v in $(ls /sys/class/net/$BR/brif); do sudo ethtool -K $v gro off gso off tso off lro off >/dev/null 2>&1; done
echo "lab up, WAN bridge: $BR"
docker exec gw-a swanctl --version | head -1
