from __future__ import annotations

import gzip
import io
import os
import stat
from pathlib import Path


def _pad(stream: io.BytesIO, boundary: int = 4) -> None:
	remaining = (-stream.tell()) % boundary
	if remaining:
		stream.write(b"\0" * remaining)


def _newc_entry(stream: io.BytesIO, name: str, data: bytes, mode: int, inode: int) -> None:
	encoded_name = name.lstrip("/").encode("utf-8") + b"\0"
	header = "070701" + "".join(f"{value:08x}" for value in (
		inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded_name), 0,
	))
	stream.write(header.encode("ascii"))
	stream.write(encoded_name)
	_pad(stream)
	stream.write(data)
	_pad(stream)


def build_newc(files: dict[str, tuple[bytes, int]]) -> bytes:
	stream = io.BytesIO()
	for inode, (name, (data, mode)) in enumerate(sorted(files.items()), start=1):
		_newc_entry(stream, name, data, stat.S_IFREG | mode, inode)
	_newc_entry(stream, "TRAILER!!!", b"", 0, len(files) + 1)
	return stream.getvalue()


def personalize_initramfs(base_initramfs: str | Path, destination: str | Path, *, manifest_path: str | Path,
	key_path: str | Path, agent_credential_path: str | Path | None = None) -> Path:
	"""Append a job-specific authenticated overlay without unpacking the base image."""
	base = Path(base_initramfs)
	destination = Path(destination)
	destination.parent.mkdir(parents=True, exist_ok=True)
	manifest = Path(manifest_path)
	key = Path(key_path)
	boot_job_id = manifest.parent.name
	files = {
		f"var/lib/vyper/boot-jobs/{boot_job_id}/manifest.json": (manifest.read_bytes(), 0o600),
		f"var/lib/vyper/boot-jobs/{boot_job_id}/state.json": ((manifest.parent / "state.json").read_bytes(), 0o600),
		"var/lib/vyper/boot-jobs/job-mac.key": (key.read_bytes(), 0o600),
		"etc/vyper/active-boot-job": ((boot_job_id + "\n").encode("utf-8"), 0o600),
	}
	if agent_credential_path and Path(agent_credential_path).is_file():
		files["etc/vyper/boot-agent-identity.json"] = (Path(agent_credential_path).read_bytes(), 0o600)
	overlay = gzip.compress(build_newc(files), compresslevel=9, mtime=0)
	with destination.open("wb") as output:
		output.write(base.read_bytes())
		output.write(overlay)
	os.chmod(destination, 0o600)
	return destination
