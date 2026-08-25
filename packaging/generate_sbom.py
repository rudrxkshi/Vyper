from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


from local_agent.sbom import generate_sbom as _generate


def generate_sbom(output: Path) -> dict:
	return _generate(output, root=ROOT)


def main() -> None:
	parser = argparse.ArgumentParser(); parser.add_argument("--output", type=Path, default=ROOT / "release/sbom.cdx.json")
	args = parser.parse_args(); print(json.dumps(generate_sbom(args.output)["metadata"], sort_keys=True))


if __name__ == "__main__": main()
