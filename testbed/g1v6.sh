#!/bin/bash
cd ~/ipsecscope/testbed || exit 1
sudo -v
PCAP=~/ipsecscope/data/g1/cbc_tunnel_ipv6.pcap
mkdir -p ~/ipsecscope/data/g1

docker network inspect wan6 >/dev/null 2>&1 || docker network create --ipv6 --subnet fd00:6::/64 wan6
docker network connect --ip6 fd00:6::2 wan6 gw-a 2>/dev/null
docker network connect --ip6 fd00:6::3 wan6 gw-b 2>/dev/null
BR=br-$(docker network inspect wan6 -f '{{.Id}}' | cut -c1-12)
echo "bridge: $BR"

for c in gw-a gw-b; do
  for i in $(docker exec $c ls /sys/class/net | grep eth); do
    docker exec $c ethtool -K $i gro off gso off tso off lro off >/dev/null 2>&1
  done
done
sudo ethtool -K $BR gro off gso off tso off lro off >/dev/null 2>&1
for v in $(ls /sys/class/net/$BR/brif); do sudo ethtool -K $v gro off gso off tso off lro off >/dev/null 2>&1; done

echo "--- plain IPv6 reachability"
docker exec gw-a ping -6 -c 2 -I fd00:6::2 fd00:6::3 | grep -E "transmitted|rror|nreachable"

mk() {
cat <<EOF
connections {
  g1v6 {
    version = 2
    local_addrs = $1
    remote_addrs = $2
    proposals = aes128-sha256-modp2048
    local  { auth = psk
             id = $3 }
    remote { auth = psk
             id = $4 }
    children {
      c {
        local_ts  = $1/128
        remote_ts = $2/128
        mode = tunnel
        esp_proposals = aes128-sha256-modp2048
      }
    }
  }
}
secrets {
  ike-1 {
    id-1 = gw-a
    id-2 = gw-b
    secret = "labpsk-change-me"
  }
}
EOF
}
mk fd00:6::2 fd00:6::3 gw-a gw-b > /tmp/g1v6-a.conf
mk fd00:6::3 fd00:6::2 gw-b gw-a > /tmp/g1v6-b.conf

for g in gw-a gw-b; do
  for n in g1 gw-gw gw-transport g1v6; do docker exec $g swanctl --terminate --ike $n >/dev/null 2>&1; done
done
sleep 2
docker cp /tmp/g1v6-a.conf gw-a:/tmp/g1v6.conf
docker cp /tmp/g1v6-b.conf gw-b:/tmp/g1v6.conf
docker exec gw-a swanctl --load-all --file /tmp/g1v6.conf 2>&1 | grep -E "successfully|failed to open|no files"
docker exec gw-b swanctl --load-all --file /tmp/g1v6.conf 2>&1 | grep -E "successfully|failed to open|no files"
docker exec gw-a swanctl --initiate --child c 2>&1 | grep -E "initiate|failed|error"
docker exec gw-a swanctl --list-sas | grep -E "ESTABLISHED|INSTALLED"

sudo timeout 25 tcpdump -i $BR -s 0 -Z $USER -w $PCAP 'ip6' &
sleep 2
for s in 8 20 56 100 200 500 1000 1200; do docker exec gw-a ping -6 -c 3 -s $s -I fd00:6::2 fd00:6::3 > /dev/null; done
wait
echo "--- count  L  L%4  (L-40)%16"
tshark -r $PCAP -Y esp -T fields -e ipv6.plen -e udp.dstport 2>/dev/null | awk '{L=$1; if ($2!="") L=L-8; print L, L%4, (L-40)%16}' | sort -n | uniq -c
echo "--- UDP port of ESP packets (blank = raw ESP)"
tshark -r $PCAP -Y esp -T fields -e udp.dstport 2>/dev/null | sort | uniq -c
