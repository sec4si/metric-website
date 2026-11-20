#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 || $# -ne 1 ]]; then
    printf '%s\n' 'Usage as root: bash ops/bootstrap.sh /path/to/metric-deploy.pub' >&2
    exit 1
fi
for program in curl flock systemctl sudo useradd visudo; do
    command -v "$program" >/dev/null
done
ops_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
deploy_key=$(< "$1")
if [[ "$deploy_key" == *$'\n'* || ! "$deploy_key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]]; then
    printf '%s\n' 'Expected one OpenSSH Ed25519 public key.' >&2
    exit 1
fi

if ! id sec4si-metric >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/sec4si-metric --shell /usr/sbin/nologin sec4si-metric
fi
if ! id metric-deploy >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/metric-deploy --shell /bin/sh metric-deploy
fi
install -d -o root -g root -m 0755 /opt/sec4si-metric /var/lib/metric-deploy /var/lib/metric-deploy/.ssh
install -d -o root -g root -m 0700 /etc/sec4si-metric
install -o root -g root -m 0755 "$ops_dir/install-release.sh" /usr/local/sbin/sec4si-metric-install
install -o root -g root -m 0755 "$ops_dir/ssh-deploy.sh" /usr/local/sbin/sec4si-metric-ssh
install -o root -g root -m 0644 "$ops_dir/sec4si-metric.service" /etc/systemd/system/sec4si-metric.service

install -o root -g root -m 0644 /dev/null /var/lib/metric-deploy/.ssh/authorized_keys
printf 'restrict,command="/usr/local/sbin/sec4si-metric-ssh" %s\n' "$deploy_key" > /var/lib/metric-deploy/.ssh/authorized_keys
sudoers=$(mktemp)
trap 'rm -f -- "$sudoers"' EXIT
printf '%s\n' 'metric-deploy ALL=(root) NOPASSWD: /usr/local/sbin/sec4si-metric-install ""' > "$sudoers"
visudo -cf "$sudoers"
install -o root -g root -m 0440 "$sudoers" /etc/sudoers.d/sec4si-metric-deploy
systemctl daemon-reload
systemctl enable sec4si-metric.service
printf '%s\n' 'Metric service and restricted deployment account installed.'
