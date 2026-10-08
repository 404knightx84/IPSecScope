#!/bin/bash
# Waits for S3 to finish, redoes the 3 W2 repeat-1 runs, then runs make eval-all.
cd ~/ipsecscope || exit 1

echo "Waiting for S3 (run_matrix finished and 0 missing runs)..."
while true; do
  if ! pgrep -f run_matrix.py >/dev/null; then
    left=$(python3 eval/missing_runs.py | grep -o 'missing or unlabeled: [0-9]*' | grep -o '[0-9]*$')
    [ "$left" = "0" ] && break
    echo "$(date +%H:%M) matrix not running but $left runs missing. Stopping, check S3."
    exit 1
  fi
  sleep 120
done
echo "S3 complete."

# Move the 3 old W2 repeat-1 runs aside (backup, not delete) so they are really redone
mkdir -p data/old_w2_r1
for t in ping web voip; do
  mv data/pcaps/w2_${t}_r1.pcap data/labels/w2_${t}_r1.json data/old_w2_r1/ 2>/dev/null
done

python3 testbed/run_matrix.py --block weak --configs W2 --repeats 1 --traffic ping,web,voip || { echo "W2 re-run failed"; exit 1; }

make eval-all
