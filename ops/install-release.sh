#!/bin/bash
set -euo pipefail

[[ $# -eq 0 ]]
umask 077
release_dir=/opt/sec4si-metric
service=sec4si-metric.service
exec 9>/run/lock/sec4si-metric-deploy.lock
flock -w 30 9
incoming=$(mktemp "$release_dir/.incoming.XXXXXX")
trap 'rm -f -- "$incoming"' EXIT

# Read at most 33 MiB and reject streams larger than the release limit.
timeout 120 dd bs=1M iflag=fullblock count=33 of="$incoming" status=none
bytes=$(stat -c '%s' "$incoming")
if (( bytes < 1 || bytes > 32 * 1024 * 1024 )); then
    printf '%s\n' 'Invalid release size.' >&2
    exit 1
fi
chmod 0755 "$incoming"
if [[ -e "$release_dir/metric" ]]; then
    cp -p -- "$release_dir/metric" "$release_dir/metric.previous"
fi
mv -T -- "$incoming" "$release_dir/metric"
if systemctl restart "$service"; then
    for _ in {1..20}; do
        if curl -fsS --max-time 1 http://127.0.0.1:9841/healthz >/dev/null; then
            printf '%s\n' 'Metric release passed the origin health check.'
            exit 0
        fi
        sleep 1
    done
fi

if [[ -e "$release_dir/metric.previous" ]]; then
    mv -T -- "$release_dir/metric.previous" "$release_dir/metric"
    systemctl restart "$service"
else
    systemctl stop "$service"
fi
printf '%s\n' 'Metric release failed its origin health check.' >&2
exit 1
