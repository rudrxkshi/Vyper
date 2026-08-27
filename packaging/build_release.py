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
from html.parser import HTMLParser
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vyper_version import __version__


ARTIFACT_NAME = f"vyper-local-console-linux-x86_64-{__version__}.tar.gz"
PRODUCT = "VYPER Local Console"
LOCAL_FRONTEND_API = "http://127.0.0.1:8765"


class _StaticAssetReferences(HTMLParser):
	def __init__(self) -> None:
		super().__init__()
		self.references: list[str] = []
		self.inline_styles: list[str] = []
		self._in_style = False

	def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
		attributes = dict(attrs)
		if tag == "link" and str(attributes.get("href") or "").split("?", 1)[0].endswith(".css"):
			self.references.append(str(attributes["href"]))
		if tag == "script" and str(attributes.get("src") or "").split("?", 1)[0].endswith(".js"):
			self.references.append(str(attributes["src"]))
		if tag == "style":
			self._in_style = True

	def handle_endtag(self, tag: str) -> None:
		if tag == "style":
			self._in_style = False

	def handle_data(self, data: str) -> None:
		if self._in_style:
			self.inline_styles.append(data)


def _export_route(export_root: Path, html: Path) -> str:
	relative = html.relative_to(export_root).as_posix()
	if relative == "index.html":
		return "/"
	if relative.endswith("/index.html"):
		return "/" + relative.removesuffix("index.html")
	return "/" + relative


def validate_embedded_static_assets(export_root: Path) -> list[str]:
	"""Validate entry assets using the URL semantics shared by Tauri and HTTP."""
	from urllib.parse import urljoin, urlsplit

	validated: list[str] = []
	dashboard_found = False
	dashboard_css_found = False
	for html in sorted(export_root.rglob("*.html")):
		html_source = html.read_text(encoding="utf-8")
		parser = _StaticAssetReferences()
		parser.feed(html_source)
		is_dashboard = 'class="nb-root"' in html_source
		if is_dashboard:
			dashboard_found = True
			if any(".nb-root" in style for style in parser.inline_styles):
				raise RuntimeError(f"Dashboard structural styles must be bundled, not inline, in {html}.")
		route = _export_route(export_root, html)
		for reference in parser.references:
			if reference.startswith("/"):
				raise RuntimeError(f"Embedded static asset uses an origin-root URL in {html}: {reference}")
			# urllib does not register Tauri's custom scheme as a hierarchical URL,
			# so use Tauri's equivalent HTTP-shaped localhost origin for RFC URL joining.
			resolved_path = urlsplit(urljoin(f"http://tauri.localhost{route}", reference)).path
			asset = export_root / resolved_path.lstrip("/")
			if not asset.is_file():
				raise RuntimeError(f"Embedded static asset reference does not exist for {html}: {reference}")
			if is_dashboard and reference.split("?", 1)[0].endswith(".css"):
				dashboard_css_found = dashboard_css_found or ".nb-root" in asset.read_text(encoding="utf-8")
			# The compatibility server uses the same URL path at its loopback origin.
			http_path = urlsplit(urljoin(f"http://127.0.0.1:8787{route}", reference)).path
			if http_path != resolved_path:
				raise RuntimeError(f"Tauri and loopback asset resolution differ for {html}: {reference}")
			validated.append(reference)
	if not validated:
		raise RuntimeError("Local console static export contains no CSS or JavaScript entry assets.")
	if dashboard_found and not dashboard_css_found:
		raise RuntimeError("Local console dashboard stylesheet is missing from bundled CSS assets.")
	return validated


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


def verify_local_frontend_export(export_root: Path) -> Path:
	index = export_root / "index.html"
	javascript = list((export_root / "_next" / "static").rglob("*.js"))
	if not index.is_file() or not javascript:
		raise RuntimeError("Local console static export is incomplete.")
	bundle = "\n".join(path.read_text(encoding="utf-8") for path in javascript)
	missing = [marker for marker in (LOCAL_FRONTEND_API, "/certificates", "/audit-logs") if marker not in bundle]
	if missing:
		raise RuntimeError(f"Local console static export is missing required integration markers: {', '.join(missing)}")
	validate_embedded_static_assets(export_root)
	metadata = export_root / "vyper-local-build.json"
	metadata.write_text(json.dumps({
		"dashboard_mode": "local",
		"local_agent_api_base_url": LOCAL_FRONTEND_API,
		"required_collections": ["/certificates", "/audit-logs"],
	}, indent=2) + "\n", encoding="utf-8")
	return metadata


def desktop_gui_artifact_path(frontend: Path, cargo_target_dir: str | Path | None = None) -> Path:
	if cargo_target_dir is None:
		target = frontend / "src-tauri" / "target"
	else:
		target = Path(cargo_target_dir).expanduser()
		if not target.is_absolute():
			# Cargo resolves a relative CARGO_TARGET_DIR against the command cwd.
			target = frontend / target
	return target.resolve() / "release" / "vyper-gui"


def validate_desktop_gui_artifact(path: Path) -> Path:
	if not path.is_file():
		raise RuntimeError(f"Tauri completed without producing the expected vyper-gui binary at {path}.")
	if os.name != "nt" and not os.access(path, os.X_OK):
		raise RuntimeError(f"Tauri GUI artifact is not executable: {path}")
	with path.open("rb") as handle:
		magic = handle.read(4)
	if magic != b"\x7fELF":
		raise RuntimeError(f"Tauri GUI artifact is not a Linux ELF executable: {path}")
	return path


def build_desktop_gui(frontend: Path, staging: Path, *, skip_builds: bool) -> Path:
	destination = staging / "vyper-gui"
	if skip_builds:
		destination.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
		return destination
	if sys.platform != "linux":
		raise RuntimeError("The VYPER Linux desktop GUI release must be built on Linux x86_64.")
	cargo = shutil.which("cargo")
	if cargo is None:
		raise RuntimeError("cargo is required to build the VYPER Tauri desktop GUI.")
	# Use an absolute target directory because Cargo resolves relative values
	# against cwd (the frontend), while release staging is rooted at the caller.
	target = (staging / "tauri-target").resolve()
	environment = os.environ.copy()
	environment["CARGO_TARGET_DIR"] = str(target)
	subprocess.run(
		[cargo, "build", "--release", "--features", "custom-protocol",
			"--manifest-path", str(frontend / "src-tauri" / "Cargo.toml")],
		cwd=frontend, env=environment, check=True,
	)
	built = validate_desktop_gui_artifact(desktop_gui_artifact_path(frontend, environment["CARGO_TARGET_DIR"]))
	shutil.copy2(built, destination)
	return validate_desktop_gui_artifact(destination)


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
			"NEXT_PUBLIC_VYPER_LOCAL_AGENT_API_BASE_URL": LOCAL_FRONTEND_API,
		})
		npm_command = shutil.which("npm") or shutil.which("npm.cmd")
		if npm_command is None:
			raise RuntimeError("npm is required to build the local console static export.")
		subprocess.run([npm_command, "run", "build"], cwd=frontend, env=environment, check=True)
	verify_local_frontend_export(frontend / "out")

	temp = output_dir / ".vyper-staging"
	temp.mkdir(parents=True, exist_ok=True)
	if any(temp.iterdir()):
		raise RuntimeError(f"Build staging directory is not empty: {temp}")
	try:
		gui_binary = build_desktop_gui(frontend, temp, skip_builds=skip_builds)
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
		(payload / "gui").mkdir(parents=True)
		(payload / "trust").mkdir(parents=True)
		for filename in ("install.sh", "uninstall.sh", "README.md"):
			shutil.copy2(ROOT / "packaging" / "linux" / filename, package_root / filename)
		shutil.copy2(ROOT / "packaging" / "linux" / "config.toml", payload / "config.toml")
		shutil.copy2(ROOT / "packaging" / "linux" / "installer.py", payload / "installer.py")
		shutil.copy2(ROOT / "requirements.lock", payload / "requirements.lock")
		shutil.copy2(ROOT / "deploy/trusted-release-keys.json", payload / "trust/trusted-release-keys.json")
		_copy_tree(ROOT / "packaging" / "linux" / "systemd", payload / "systemd")
		shutil.copy2(gui_binary, payload / "gui" / "vyper-gui")
		shutil.copy2(ROOT / "packaging" / "linux" / "desktop" / "vyper.desktop", payload / "gui" / "vyper.desktop")
		shutil.copy2(ROOT / "packaging" / "linux" / "desktop" / "vyper.svg", payload / "gui" / "vyper.svg")
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
			"desktop_gui": {"enabled": True, "technology": "tauri", "port_8787_required": False},
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
		"desktop_gui": {"enabled": True, "technology": "tauri", "port_8787_required": False},
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
