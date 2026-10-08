#!/bin/bash
# usage: ./g1.sh NAME MODE ESP_PROPOSAL
NAME=$1; MODE=$2; ESP=$3
cd ~/ipsecscope/testbed || exit 1
sudo -v
WAN_BR=br-$(docker network inspect testbed_wan -f '{{.Id}}' | cut -c1-12)
PCAP=~/ipsecscope/data/g1/$NAME.pcap
mkdir -p ~/ipsecscope/data/g1

mk() {
cat <<EOF
connections {
  g1 {
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
        local_ts  = $1/32
        remote_ts = $2/32
        mode = $MODE
        esp_proposals = $ESP
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
mk 10.0.0.2 10.0.0.3 gw-a gw-b > /tmp/g1-a.conf
mk 10.0.0.3 10.0.0.2 gw-b gw-a > /tmp/g1-b.conf

for g in gw-a gw-b; do
  for n in gw-gw gw-transport g1; do docker exec $g swanctl --terminate --ike $n >/dev/null 2>&1; done
done
sleep 2
docker cp /tmp/g1-a.conf gw-a:/tmp/g1.conf
docker cp /tmp/g1-b.conf gw-b:/tmp/g1.conf
docker exec gw-a swanctl --load-all --file /tmp/g1.conf 2>&1 | grep -E "successfully|failed to open|no files"
docker exec gw-b swanctl --load-all --file /tmp/g1.conf 2>&1 | grep -E "successfully|failed to open|no files"
docker exec gw-a swanctl --initiate --child c 2>&1 | grep -E "initiate|failed|error"
docker exec gw-a swanctl --list-sas | grep -E "ESTABLISHED|INSTALLED"

sudo timeout 25 tcpdump -i $WAN_BR -s 0 -Z $USER -w $PCAP 'udp port 500 or udp port 4500 or esp' &
sleep 2
for s in 8 20 56 100 200 500 1000 1400; do docker exec gw-a ping -c 3 -s $s 10.0.0.3 > /dev/null; done
wait
echo "--- count  L  L%4  (L-40)%16"
tshark -r $PCAP -Y esp -T fields -e ip.len -e ip.hdr_len -e udp.dstport 2>/dev/null | awk '{L=$1-$2; if ($3!="") L=L-8; print L, L%4, (L-40)%16}' | sort -n | uniq -c
echo "--- UDP port of ESP packets (blank = raw ESP)"
tshark -r $PCAP -Y esp -T fields -e udp.dstport 2>/dev/null | sort | uniq -c
