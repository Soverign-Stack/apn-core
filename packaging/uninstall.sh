#!/bin/sh
# Remove the APN node service.
#
#   sudo ./uninstall.sh           remove the program and the service,
#                                 KEEP the identity and settings
#   sudo ./uninstall.sh --purge   also delete the identity, claim code,
#                                 settings and the "apn" user (cannot be undone)
set -eu

SERVICE=apn-node.service
PURGE=no
[ "${1:-}" = "--purge" ] && PURGE=yes

[ "$(id -u)" -eq 0 ] || { echo "run it with sudo:  sudo ./uninstall.sh" >&2; exit 1; }

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$SERVICE" 2>/dev/null || true
fi
rm -f "/etc/systemd/system/$SERVICE"
rm -f /usr/local/bin/apn_node /usr/local/bin/apn
rm -rf /usr/local/share/doc/apn-node
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
echo "Removed the APN node program and service."

if [ "$PURGE" = yes ]; then
    rm -rf /var/lib/apn /etc/apn
    if id apn >/dev/null 2>&1; then
        userdel apn 2>/dev/null || true
    fi
    echo "Deleted the node identity, claim code, settings and the 'apn' user."
    echo "If the node was claimed, also remove it in the Dashboard."
else
    echo "Kept /var/lib/apn (identity, claim code) and /etc/apn (settings)."
    echo "To delete those too:  sudo ./uninstall.sh --purge"
fi
