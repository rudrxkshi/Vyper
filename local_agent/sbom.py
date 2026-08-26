from __future__ import annotations

import json
from pathlib import Path

from vyper_version import __version__


def generate_sbom(output: Path, *, root: Path | None = None) -> dict:
	root = root or Path(__file__).resolve().parents[1]
	components = [{"type": "application", "name": "vyper-local-console", "version": __version__}]
	for requirement_file in (root / "requirements.lock", root / "requirements-central.lock"):
		for line in requirement_file.read_text(encoding="utf-8").splitlines():
			if "==" in line and not line.startswith("#"):
				name, version = line.split("==", 1)
				components.append({"type": "library", "name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}"})
	lock = json.loads((root / "frontend/user-dashboard/package-lock.json").read_text(encoding="utf-8"))
	for name, item in sorted((lock.get("packages") or {}).items()):
		if name.startswith("node_modules/") and item.get("version"):
			package = name.split("node_modules/", 1)[1]
			components.append({"type": "library", "name": package, "version": item["version"], "purl": f"pkg:npm/{package}@{item['version']}"})
	for tool in ("lsblk", "findmnt", "hdparm", "nvme-cli", "util-linux", "smartmontools", "grub2", "initramfs-tools"):
		components.append({"type": "application", "name": tool, "version": "provided-by-target-linux-distribution"})
	unique = {(item["type"], item["name"], item["version"]): item for item in components}
	payload = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"metadata": {"component": {"type": "application", "name": "VYPER", "version": __version__}},
		"components": list(unique.values())}
	output.parent.mkdir(parents=True, exist_ok=True); output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
	return payload
