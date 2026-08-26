#!/bin/sh
set -eu

fail() { printf 'VYPER installer: %s\n' "$1" >&2; exit 1; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_ROOT=${VYPER_INSTALL_ROOT:-}
TEST_MODE=${VYPER_INSTALL_TEST_MODE:-0}

case "$INSTALL_ROOT" in
  ""|/*) ;;
  *) fail "VYPER_INSTALL_ROOT must be an absolute path" ;;
esac

if [ "$TEST_MODE" != "1" ]; then
  [ "$(id -u)" -eq 0 ] || fail "run this installer as root"
  [ "$(uname -s)" = "Linux" ] || fail "Stage 5 supports Linux only"
  case "$(uname -m)" in x86_64|amd64) ;; *) fail "Stage 5 supports x86_64 only" ;; esac
  command -v python3 >/dev/null 2>&1 || fail "Python 3.11 or newer is required"
  python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)' || fail "Python 3.11 or newer is required"
  for command in lsblk hdparm nvme smartctl systemctl mkinitramfs lsinitramfs grub-reboot grub-editenv update-grub swapoff findmnt pvs; do
    command -v "$command" >/dev/null 2>&1 || fail "required command missing: $command"
  done
fi

root_arg=${INSTALL_ROOT:-/}
if [ "$TEST_MODE" = "1" ]; then
  python3 "$SCRIPT_DIR/payload/installer.py" install --package-root "$SCRIPT_DIR" --root "$root_arg" --test-mode
else
  python3 "$SCRIPT_DIR/payload/installer.py" install --package-root "$SCRIPT_DIR" --root "$root_arg"
fi

opt="$INSTALL_ROOT/opt/vyper"
etc="$INSTALL_ROOT/etc/vyper"
state="$INSTALL_ROOT/var/lib/vyper"
logs="$INSTALL_ROOT/var/log/vyper"

if [ "$TEST_MODE" != "1" ]; then
	if ! getent group vyper-executor >/dev/null 2>&1; then groupadd --system vyper-executor; fi
	if ! id vyper-agent >/dev/null 2>&1; then
		useradd --system --gid vyper-executor --home-dir /nonexistent --shell /usr/sbin/nologin vyper-agent
	fi
	if ! id vyper-ui >/dev/null 2>&1; then
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin vyper-ui
  fi
	usermod -a -G vyper-executor vyper-ui
  chown root:vyper-executor "$etc" "$etc/config.toml"
  chmod 0750 "$etc"
  chmod 0640 "$etc/config.toml"
  if [ -f "$etc/agent-identity.json" ]; then chown vyper-agent:vyper-executor "$etc/agent-identity.json"; chmod 0600 "$etc/agent-identity.json"; fi
	chown -R root:root "$opt"
	chown -R vyper-agent:vyper-executor "$state" "$logs"
  python3 -m venv "$opt/runtime"
  "$opt/runtime/bin/pip" install --disable-pip-version-check -r "$SCRIPT_DIR/payload/requirements.lock"
  "$opt/runtime/bin/pip" install --disable-pip-version-check --force-reinstall --no-deps "$SCRIPT_DIR"/payload/wheels/vyper_local_console-*.whl
  "$opt/runtime/bin/python" "$opt/boot/build_boot_image.py" --output-dir "$opt/boot"
fi

if [ "$TEST_MODE" != "1" ]; then
  systemctl daemon-reload
	systemctl enable --now vyper-executor.service vyper-agent.service vyper-console.service
fi

printf 'VYPER Local Console installed.\nNext: vyper enroll\nThen: vyper open\n'
