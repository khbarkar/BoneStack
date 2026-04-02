#!/bin/sh
set -eu

echo "[demo] ai-followup-demo booting"
echo "[demo] loaded scheduled task from /etc/cron.d/ai-followup"
echo "[demo] suspicious-looking helper script staged at /opt/demo/bootstrap.sh"
echo "[demo] outbound callback simulation is disabled; this container is for training only"
echo "[demo] review logs and timeline before assuming compromise"

crond

while true; do
  echo "[demo] heartbeat $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  sleep 15
done
