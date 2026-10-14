#!/usr/bin/env bash
# run_sweep.sh — launch N resumable bf2.py workers covering a code range.
#
# Usage: ./run_sweep.sh <email> <lo> <hi> <workers> [prefix]
#   e.g. ./run_sweep.sh security@vodafone.om 0 3600 2 /tmp/vfo_r
#
# Splits lo..hi into N contiguous slices, one worker each. Safe to re-run:
# workers resume from their saved position (statedir/pos). Stop a worker:
# touch <statedir>/bf_stop. Hit: <statedir>/bf_SUCCESS.json.
set -euo pipefail
cd "$(dirname "$0")"

if [ $# -lt 4 ]; then
  echo "usage: $0 <email> <lo> <hi> <workers> [prefix=/tmp/vfo_r]"
  exit 1
fi
email=$1; lo=$2; hi=$3; n=$4; prefix=${5:-/tmp/vfo_r}
span=$((hi - lo))
per=$((span / n))
[ $per -lt 1 ] && { echo "too few values for $n workers"; exit 1; }

i=0
while [ $i -lt $n ]; do
  a=$((lo + i * per))
  if [ $i -eq $((n - 1)) ]; then b=$hi; else b=$((lo + (i + 1) * per)); fi
  d="$prefix$i"
  mkdir -p "$d"
  if pgrep -f "bf2[.]py $email $a $b" > /dev/null; then
    echo "worker $i ($a-$b): already running -> $d"
  else
    nohup python3 bf2.py "$email" "$a" "$b" "$d" > "$d/out.log" 2>&1 < /dev/null &
    echo "worker $i ($a-$b): launched pid $! -> $d"
    sleep 8
  fi
  i=$((i + 1))
done
echo "monitor:  tail -f $prefix*/out.log"
echo "success:  ls $prefix*/bf_SUCCESS.json"
