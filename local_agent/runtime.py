from __future__ import annotations

from .config import apply_runtime_environment


def agent_main() -> None:
	apply_runtime_environment()
	from .main import main

	main()


if __name__ == "__main__":
	agent_main()
