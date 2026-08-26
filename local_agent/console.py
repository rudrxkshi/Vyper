from __future__ import annotations

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from .config import load_config, ui_path


class QuietStaticHandler(SimpleHTTPRequestHandler):
	def log_message(self, format: str, *args) -> None:
		return


def main() -> None:
	config = load_config()
	if config.local_console_bind not in {"127.0.0.1", "::1", "localhost"}:
		raise RuntimeError("The packaged local console must bind to loopback.")
	handler = partial(QuietStaticHandler, directory=str(ui_path()))
	server = ThreadingHTTPServer((config.local_console_bind, config.local_console_port), handler)
	server.serve_forever()


if __name__ == "__main__":
	main()
