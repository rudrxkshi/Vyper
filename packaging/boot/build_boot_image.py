from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from local_agent.boot_image import build_fixture_boot_image, build_host_boot_image


def main() -> None:
	parser = argparse.ArgumentParser(description="Build the VYPER Ubuntu/Debian x86_64 boot environment")
	parser.add_argument("--output-dir", type=Path, default=ROOT / "release" / "boot")
	parser.add_argument("--kernel-version")
	parser.add_argument("--fixture", action="store_true", help="Build a non-bootable CI fixture; never use for handoff")
	args = parser.parse_args()
	manifest = build_fixture_boot_image(args.output_dir) if args.fixture else build_host_boot_image(
		args.output_dir, kernel_version=args.kernel_version,
	)
	print(manifest)


if __name__ == "__main__":
	main()
