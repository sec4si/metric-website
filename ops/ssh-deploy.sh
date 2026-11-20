#!/bin/sh
set -eu

if [ "${SSH_ORIGINAL_COMMAND:-}" != "deploy-metric" ]; then
    printf '%s\n' 'This key accepts only deploy-metric.' >&2
    exit 1
fi
exec /usr/bin/sudo -n /usr/local/sbin/sec4si-metric-install
