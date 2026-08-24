from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path


COMMANDS = ("vyper", "vyper-agent", "vyper-local-agent", "vyper-console", "vyper-diagnose")


def _under(root: Path, absolute: str) -> Path:
	if not absolute.startswith("/"):
		raise ValueError("Installation paths must be absolute.")
	return root / absolute.lstrip("/")


def install_layout(package_root: Path, root: Path, *, test_mode: bool = False) -> None:
	root = root.resolve()
	opt = _under(root, "/opt/vyper")
	config_dir = _under(root, "/etc/vyper")
	state = _under(root, "/var/lib/vyper")
	logs = _under(root, "/var/log/vyper")
	units = _under(root, "/etc/systemd/system")
	initramfs_hooks = _under(root, "/etc/initramfs-tools/hooks")
	initramfs_scripts = _under(root, "/etc/initramfs-tools/scripts/local-premount")
	bin_dir = _under(root, "/usr/bin")
	for path, mode in ((opt, 0o755), (config_dir, 0o750), (state, 0o700), (logs, 0o750), (units, 0o755),
		(initramfs_hooks, 0o755), (initramfs_scripts, 0o755), (bin_dir, 0o755)):
		path.mkdir(parents=True, exist_ok=True)
		os.chmod(path, mode)
	(opt / "ui").mkdir(exist_ok=True)
	(opt / "runtime").mkdir(exist_ok=True)
	(opt / "boot").mkdir(exist_ok=True)
	(opt / "docs").mkdir(exist_ok=True)
	shutil.copy2(package_root / "manifest.json", opt / "manifest.json")
	shutil.copy2(package_root / "payload" / "VERSION", opt / "VERSION")
	shutil.copytree(package_root / "payload" / "ui", opt / "ui", dirs_exist_ok=True)
	shutil.copytree(package_root / "payload" / "docs", opt / "docs", dirs_exist_ok=True)
	shutil.copy2(package_root / "payload" / "boot" / "build_boot_image.py", opt / "boot" / "build_boot_image.py")
	shutil.copy2(package_root / "payload" / "boot" / "initramfs-tools" / "hooks" / "vyper", initramfs_hooks / "vyper")
	shutil.copy2(package_root / "payload" / "boot" / "initramfs-tools" / "scripts" / "local-premount" / "vyper", initramfs_scripts / "vyper")
	os.chmod(initramfs_hooks / "vyper", 0o755)
	os.chmod(initramfs_scripts / "vyper", 0o755)
	for unit in ("vyper-agent.service", "vyper-console.service"):
		shutil.copy2(package_root / "payload" / "systemd" / unit, units / unit)
		os.chmod(units / unit, 0o644)
	config = config_dir / "config.toml"
	if not config.exists():
		shutil.copy2(package_root / "payload" / "config.toml", config)
		os.chmod(config, 0o640)
	if test_mode:
		runtime_bin = opt / "runtime" / "bin"
		runtime_bin.mkdir(parents=True, exist_ok=True)
		for command in COMMANDS:
			(runtime_bin / command).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
			os.chmod(runtime_bin / command, 0o755)
	for command in COMMANDS:
		wrapper = bin_dir / command
		wrapper.write_text(f'#!/bin/sh\nexec /opt/vyper/runtime/bin/{command} "$@"\n', encoding="utf-8")
		os.chmod(wrapper, 0o755)


def uninstall_layout(root: Path, *, purge: bool = False) -> None:
	root = root.resolve()
	for command in COMMANDS:
		_under(root, f"/usr/bin/{command}").unlink(missing_ok=True)
	for unit in ("vyper-agent.service", "vyper-console.service"):
		_under(root, f"/etc/systemd/system/{unit}").unlink(missing_ok=True)
	_under(root, "/etc/initramfs-tools/hooks/vyper").unlink(missing_ok=True)
	_under(root, "/etc/initramfs-tools/scripts/local-premount/vyper").unlink(missing_ok=True)
	shutil.rmtree(_under(root, "/opt/vyper"), ignore_errors=True)
	if purge:
		for absolute in ("/etc/vyper", "/var/lib/vyper", "/var/log/vyper"):
			shutil.rmtree(_under(root, absolute), ignore_errors=True)


def main() -> None:
	parser = argparse.ArgumentParser()
	parser.add_argument("action", choices=("install", "uninstall"))
	parser.add_argument("--package-root", type=Path, default=Path(__file__).resolve().parents[1])
	parser.add_argument("--root", type=Path, default=Path("/"))
	parser.add_argument("--test-mode", action="store_true")
	parser.add_argument("--purge", action="store_true")
	args = parser.parse_args()
	if args.action == "install":
		install_layout(args.package_root, args.root, test_mode=args.test_mode)
	else:
		uninstall_layout(args.root, purge=args.purge)


if __name__ == "__main__":
	main()
