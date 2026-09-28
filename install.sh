#!/bin/bash
# Build omafind, install it root-owned in /usr/local/bin, allow the daemon to
# drive the nftables helper without a password, and add the bar widget.
#
#   ./install.sh              install / update
#   ./install.sh --uninstall  remove everything (rules in ~/.config/omafind are kept)

set -euo pipefail
cd "$(dirname "$0")"

BIN=/usr/local/bin/omafind
SUDOERS=/etc/sudoers.d/omafind
PLUGIN_ID=ben.omafind
PLUGIN_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/plugins/$PLUGIN_ID"

# Run a bash snippet as root in one go: sudo when there's a terminal to ask
# for the password, otherwise pkexec (graphical prompt from the shell's agent).
as_root() {
  local script=$1
  shift
  if [[ -t 0 ]] || sudo -n true 2>/dev/null; then
    sudo bash -c "$script" omafind-install "$@"
  else
    pkexec bash -c "$script" omafind-install "$@"
  fi
}

if [[ ${1:-} == --uninstall ]]; then
  omarchy plugin disable "$PLUGIN_ID" 2>/dev/null || true
  rm -rf "$PLUGIN_DIR"
  as_root '[[ -x $1 ]] && "$1" firewall clear || true; rm -f "$1" "$2"' "$BIN" "$SUDOERS"
  omarchy-shell shell rescanPlugins >/dev/null 2>&1 || true
  echo "omafind removed"
  exit 0
fi

cargo build --release

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
echo "$USER ALL=(root) NOPASSWD: $BIN firewall *" >"$tmp"
chmod 644 "$tmp"

# The binary must be root-owned: sudoers lets it run as root without a password.
as_root '
  set -e
  install -Dm755 -o root -g root "$1" "$2"
  visudo -cqf "$3"
  install -m440 -o root -g root "$3" "$4"
' "$PWD/target/release/omafind" "$BIN" "$tmp" "$SUDOERS"

mkdir -p "$PLUGIN_DIR"
cp plugin/manifest.json plugin/*.qml "$PLUGIN_DIR/"
omarchy-shell shell rescanPlugins >/dev/null 2>&1 || true

if ! jq -e --arg id "$PLUGIN_ID" '[.bar.layout[][]?.id] | index($id)' \
  "${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/shell.json" >/dev/null 2>&1; then
  omarchy plugin enable "$PLUGIN_ID" --section right --before omarchy.network ||
    omarchy plugin enable "$PLUGIN_ID" --section right
fi

echo "omafind installed. Try: omafind list"
