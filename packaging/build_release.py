from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vyper_version import __version__


ARTIFACT_NAME = f"vyper-local-console-linux-x86_64-{__version__}.tar.gz"
PRODUCT = "VYPER Local Console"


def sha256_file(path: Path) -> str:
	digest = hashlib.sha256()
	with path.open("rb") as handle:
		for chunk in iter(lambda: handle.read(1024 * 1024), b""):
			digest.update(chunk)
	return digest.hexdigest()


def _copy_tree(source: Path, destination: Path) -> None:
	shutil.copytree(source, destination, dirs_exist_ok=True,
		ignore=shutil.ignore_patterns("*.map", "*.pyc", "__pycache__", ".pytest_cache"))


def _payload_checksums(package_root: Path) -> tuple[str, int, list[str]]:
	lines = []
	total = 0
	for path in sorted(item for item in package_root.rglob("*") if item.is_file() and item.name not in {"manifest.json", "checksums.txt"}):
		relative = path.relative_to(package_root).as_posix()
		total += path.stat().st_size
		lines.append(f"{sha256_file(path)}  {relative}")
	digest = hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()
	return digest, total, lines


def _write_deterministic_tar(source: Path, destination: Path) -> None:
	epoch = int(os.getenv("SOURCE_DATE_EPOCH", "1787529600"))
	with destination.open("wb") as raw:
		with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
			with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
				for path in sorted([source, *source.rglob("*")]):
					arcname = path.relative_to(source.parent).as_posix()
					info = archive.gettarinfo(str(path), arcname)
					info.mtime = epoch
					info.uid = 0
					info.gid = 0
					info.uname = "root"
					info.gname = "root"
					if path.name in {"install.sh", "uninstall.sh"}:
						info.mode = 0o755
					if path.is_file():
						with path.open("rb") as handle:
							archive.addfile(info, handle)
					else:
						archive.addfile(info)


def build_release(*, output_dir: Path, skip_builds: bool = False, skip_frontend_build: bool = False) -> Path:
	output_dir.mkdir(parents=True, exist_ok=True)
	from local_agent.sbom import generate_sbom
	sbom = output_dir / "sbom.cdx.json"
	generate_sbom(sbom, root=ROOT)
	frontend = ROOT / "frontend" / "user-dashboard"
	if not skip_builds and not skip_frontend_build:
		environment = os.environ.copy()
		environment.update({
			"NEXT_PUBLIC_VYPER_MODE": "local",
			"NEXT_PUBLIC_VYPER_LOCAL_AGENT_API_BASE_URL": "http://127.0.0.1:8765",
		})
		npm_command = shutil.which("npm") or shutil.which("npm.cmd")
		if npm_command is None:
			raise RuntimeError("npm is required to build the local console static export.")
		subprocess.run([npm_command, "run", "build"], cwd=frontend, env=environment, check=True)

	temp = output_dir / ".vyper-staging"
	temp.mkdir(parents=True, exist_ok=True)
	if any(temp.iterdir()):
		raise RuntimeError(f"Build staging directory is not empty: {temp}")
	try:
		wheel_dir = temp / "wheels"
		wheel_dir.mkdir()
		if not skip_builds:
			pip_temp = temp / "pip-temp"
			pip_temp.mkdir()
			pip_environment = os.environ.copy()
			pip_environment.update({
				"TEMP": str(pip_temp),
				"TMP": str(pip_temp),
				"SOURCE_DATE_EPOCH": os.getenv("SOURCE_DATE_EPOCH", "1787529600"),
			})
			subprocess.run(
				[sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--wheel-dir", str(wheel_dir)],
				cwd=ROOT,
				env=pip_environment,
				check=True,
			)
		else:
			(wheel_dir / f"vyper_local_console-{__version__}-py3-none-any.whl").write_bytes(b"test-wheel")

		package_root = temp / f"vyper-local-console-{__version__}"
		payload = package_root / "payload"
		(payload / "wheels").mkdir(parents=True)
		(payload / "trust").mkdir(parents=True)
		for filename in ("install.sh", "uninstall.sh", "README.md"):
			shutil.copy2(ROOT / "packaging" / "linux" / filename, package_root / filename)
		shutil.copy2(ROOT / "packaging" / "linux" / "config.toml", payload / "config.toml")
		shutil.copy2(ROOT / "packaging" / "linux" / "installer.py", payload / "installer.py")
		shutil.copy2(ROOT / "requirements.lock", payload / "requirements.lock")
		shutil.copy2(ROOT / "deploy/trusted-release-keys.json", payload / "trust/trusted-release-keys.json")
		_copy_tree(ROOT / "packaging" / "linux" / "systemd", payload / "systemd")
		_copy_tree(ROOT / "packaging" / "boot", payload / "boot")
		_copy_tree(ROOT / "docs", payload / "docs")
		_copy_tree(ROOT / "demo-fixtures", payload / "demo-fixtures")
		shutil.copy2(sbom, payload / "sbom.cdx.json")
		_copy_tree(frontend / "out", payload / "ui")
		_copy_tree(wheel_dir, payload / "wheels")
		(payload / "VERSION").write_text(__version__ + "\n", encoding="utf-8")

		payload_hash, payload_size, checksums = _payload_checksums(package_root)
		(package_root / "checksums.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")
		internal_manifest = {
			"product": PRODUCT,
			"version": __version__,
			"platform": "linux",
			"architecture": "x86_64",
			"agent_protocol_version": "1",
			"local_api_version": "2",
			"checksum_scope": "archive payload excluding manifest.json and checksums.txt",
			"payload_sha256": payload_hash,
			"payload_size_bytes": payload_size,
		}
		(package_root / "manifest.json").write_text(json.dumps(internal_manifest, indent=2) + "\n", encoding="utf-8")

		artifact = output_dir / ARTIFACT_NAME
		_write_deterministic_tar(package_root, artifact)
	finally:
		# The staging directory is intentionally retained empty on platforms where
		# security software prevents safe temporary-directory removal.
		for path in sorted(temp.rglob("*"), reverse=True):
			if path.is_file() or path.is_symlink():
				path.unlink()
			elif path.is_dir():
				path.rmdir()

	archive_hash = sha256_file(artifact)
	release_date = datetime.now(timezone.utc).date().isoformat()
	manifest = {
		"product": PRODUCT,
		"version": __version__,
		"platform": "linux",
		"architecture": "x86_64",
		"filename": artifact.name,
		"sha256": archive_hash,
		"size_bytes": artifact.stat().st_size,
		"release_date": release_date,
		"download_url": f"/downloads/{artifact.name}",
		"minimum_agent_protocol": "1",
		"minimum_local_api_version": "2",
		"signature_status": "UNSIGNED",
		"integrity_status": "CHECKSUM_ONLY",
		"signature_type": None,
		"signature_file": None,
		"signature_key_id": None,
		"sbom": {"filename": sbom.name, "format": "CycloneDX", "spec_version": "1.6", "sha256": sha256_file(sbom)},
	}
	(output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
	(output_dir / "checksums.txt").write_text(f"{archive_hash}  {artifact.name}\n", encoding="utf-8")
	return artifact


def main() -> None:
	parser = argparse.ArgumentParser()
	parser.add_argument("--output-dir", type=Path, default=ROOT / "release")
	parser.add_argument("--skip-builds", action="store_true", help=argparse.SUPPRESS)
	parser.add_argument("--skip-frontend-build", action="store_true", help=argparse.SUPPRESS)
	args = parser.parse_args()
	artifact = build_release(
		output_dir=args.output_dir,
		skip_builds=args.skip_builds,
		skip_frontend_build=args.skip_frontend_build,
	)
	print(artifact)


if __name__ == "__main__":
	main()
