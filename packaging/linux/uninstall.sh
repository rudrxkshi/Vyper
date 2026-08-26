#!/bin/sh
set -eu

fail() { printf 'VYPER uninstaller: %s\n' "$1" >&2; exit 1; }
INSTALL_ROOT=${VYPER_INSTALL_ROOT:-}
TEST_MODE=${VYPER_INSTALL_TEST_MODE:-0}
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ $# -le 1 ] || fail "usage: ./uninstall.sh [--purge]"
case "$INSTALL_ROOT" in ""|/*) ;; *) fail "VYPER_INSTALL_ROOT must be absolute" ;; esac

if [ "$TEST_MODE" != "1" ]; then
  [ "$(id -u)" -eq 0 ] || fail "run this uninstaller as root"
  systemctl disable --now vyper-console.service vyper-agent.service 2>/dev/null || true
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root_arg=${INSTALL_ROOT:-/}
if [ "$PURGE" -eq 1 ]; then
  python3 "$SCRIPT_DIR/payload/installer.py" uninstall --root "$root_arg" --purge
else
  python3 "$SCRIPT_DIR/payload/installer.py" uninstall --root "$root_arg"
fi

if [ "$PURGE" -eq 1 ]; then
  if [ "$TEST_MODE" != "1" ] && id vyper-ui >/dev/null 2>&1; then userdel vyper-ui; fi
  printf 'VYPER removed, including configuration, credentials, job history, outbox, evidence, and logs.\n'
else
  printf 'VYPER application removed. /etc/vyper, /var/lib/vyper, and /var/log/vyper were preserved.\n'
fi

if [ "$TEST_MODE" != "1" ]; then systemctl daemon-reload; fi
