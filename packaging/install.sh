#!/bin/sh
# Install the APN node as a systemd service.
#
#   sudo ./install.sh [path/to/apn_node]
#
# Installs the binary you already have (default: ./apn_node next to this
# script). Downloads nothing, contains no secrets, and does not start the
# node: you start it yourself once /etc/apn/node.env is right.
# Safe to run again to upgrade the binary; settings and identity are kept.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
BINARY="${1:-$HERE/apn_node}"

BIN_DIR=/usr/local/bin
ETC_DIR=/etc/apn
STATE_DIR=/var/lib/apn
UNIT_DIR=/etc/systemd/system
DOC_DIR=/usr/local/share/doc/apn-node
SERVICE=apn-node.service
SVC_USER=apn

fail() { echo "install.sh: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run it with sudo:  sudo ./install.sh"
[ "$(uname -s)" = "Linux" ] || fail "this installer is for Linux only"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "this build is for 64-bit Intel/AMD (x86_64) machines; this one is $(uname -m)" ;;
esac
command -v systemctl >/dev/null 2>&1 || fail "systemd (systemctl) is required"
[ -f "$BINARY" ] || fail "node program not found at $BINARY (pass its path: sudo ./install.sh /path/to/apn_node)"
for f in apn-node.service node.env.example apn; do
    [ -f "$HERE/$f" ] || fail "missing $f next to install.sh"
done

# The file must be the node program and must run on this machine.
"$BINARY" --version >/dev/null 2>&1 || fail "$BINARY does not run on this machine"
VERSION="$("$BINARY" --version)"

echo "Installing $VERSION"

# 1. Dedicated unprivileged account: no login shell, no password.
if ! id "$SVC_USER" >/dev/null 2>&1; then
    NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
    useradd --system --user-group --home-dir "$STATE_DIR" --no-create-home \
        --shell "$NOLOGIN" --comment "APN node" "$SVC_USER"
    echo "  created system user '$SVC_USER'"
fi

# 2. Stop a running node before replacing its program.
WAS_ACTIVE=no
if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    WAS_ACTIVE=yes
    systemctl stop "$SERVICE"
fi

# 3. Program and helper.
install -d -m 0755 "$BIN_DIR"
install -m 0755 -o root -g root "$BINARY" "$BIN_DIR/apn_node"
install -m 0755 -o root -g root "$HERE/apn" "$BIN_DIR/apn"
echo "  installed $BIN_DIR/apn_node and $BIN_DIR/apn"

# 4. State directory: identity and claim code, readable by the node only.
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR"

# 5. Settings: never overwrite an existing file.
install -d -m 0750 -o root -g "$SVC_USER" "$ETC_DIR"
if [ -f "$ETC_DIR/node.env" ]; then
    echo "  kept existing $ETC_DIR/node.env"
else
    install -m 0640 -o root -g "$SVC_USER" "$HERE/node.env.example" "$ETC_DIR/node.env"
    echo "  created $ETC_DIR/node.env"
fi

# 6. Service definition and guide.
install -m 0644 -o root -g root "$HERE/apn-node.service" "$UNIT_DIR/$SERVICE"
if [ -f "$HERE/INSTALL.md" ]; then
    install -d -m 0755 "$DOC_DIR"
    install -m 0644 "$HERE/INSTALL.md" "$DOC_DIR/INSTALL.md"
fi
systemctl daemon-reload
echo "  installed $UNIT_DIR/$SERVICE"

if [ "$WAS_ACTIVE" = yes ]; then
    systemctl start "$SERVICE"
    echo
    echo "Upgrade done, the node was restarted. Check it:  sudo apn status"
    exit 0
fi

cat <<NEXT

Installed. The node is not running yet. Next:

  1. Check the settings (relay address, login if you were given one):
         sudo nano $ETC_DIR/node.env
  2. Start the node now and at every boot:
         sudo systemctl enable --now $SERVICE
  3. Get the claim code and enter it in the Dashboard:
         sudo apn claim-code
  4. Check that it is connected:
         sudo apn status
NEXT
