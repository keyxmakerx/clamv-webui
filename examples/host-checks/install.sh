#!/bin/sh
# Install clamv's host-check units and polkit rule on this host; run as root once.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
uid=${CLAMV_UID:-10001}
if ! id clamv >/dev/null 2>&1; then
  if getent passwd "$uid" >/dev/null; then
    echo "uid $uid is taken; set CLAMV_UID to the uid clamv's container runs as" >&2
    exit 1
  fi
  useradd --system --uid "$uid" --no-create-home --shell /usr/sbin/nologin clamv
fi
install -d -m 0755 /usr/local/libexec/clamv /var/log/aide
install -m 0755 "$here/aide-accept" /usr/local/libexec/clamv/aide-accept
for u in clamv-aide-check.service clamv-aide-check.timer clamv-aide-accept.service \
         clamv-rkhunter-check.service clamv-rkhunter-check.timer clamv-rkhunter-propupd.service; do
  install -m 0644 "$here/$u" "/etc/systemd/system/$u"
done
install -d -m 0755 /etc/polkit-1/rules.d
install -m 0644 "$here/50-clamv-host-checks.rules" /etc/polkit-1/rules.d/50-clamv-host-checks.rules
systemctl daemon-reload
echo "Installed. Turn the daily timers on from clamv's Host Checks page."
