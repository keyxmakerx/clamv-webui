#!/bin/sh
# Install Palisade's host-check units and polkit rule on this host; run as root once.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
uid=${PALISADE_UID:-10001}
if ! id palisade >/dev/null 2>&1; then
  if getent passwd "$uid" >/dev/null; then
    echo "uid $uid is taken; set PALISADE_UID to the uid Palisade's container runs as" >&2
    exit 1
  fi
  useradd --system --uid "$uid" --no-create-home --shell /usr/sbin/nologin palisade
fi
install -d -m 0755 /usr/local/libexec/palisade /var/log/aide
install -d -m 0750 -o palisade -g root /var/lib/palisade/firewall /var/lib/palisade/timers
install -d -m 0755 /etc/systemd/system/palisade-aide-check.timer.d /etc/systemd/system/palisade-rkhunter-check.timer.d
for s in aide-accept firewall-snapshot firewall-apply firewall-remove firewall-lib timer-set; do
  install -m 0755 "$here/$s" "/usr/local/libexec/palisade/$s"
done
for u in palisade-aide-check.service palisade-aide-check.timer palisade-aide-accept.service \
         palisade-rkhunter-check.service palisade-rkhunter-check.timer palisade-rkhunter-propupd.service \
         palisade-firewall-snapshot.service palisade-firewall-apply.service palisade-firewall-remove.service \
         palisade-timer-set.service; do
  install -m 0644 "$here/$u" "/etc/systemd/system/$u"
done
install -d -m 0755 /etc/polkit-1/rules.d
install -m 0644 "$here/50-palisade-host-checks.rules" /etc/polkit-1/rules.d/50-palisade-host-checks.rules
systemctl daemon-reload
echo "Installed. Mount /var/lib/palisade/firewall read-write into Palisade for the Firewall page."
