from __future__ import annotations

import errno

import pytest

from local_agent.privileged_executor import PrivilegedExecutorClient, _send_response


class FakeSocket:
	def __init__(self, response=b'{"result":[]}\n', send_error=None):
		self.response = response
		self.send_error = send_error
		self.timeouts = []

	def __enter__(self): return self
	def __exit__(self, *_args): return False
	def settimeout(self, value): self.timeouts.append(value)
	def connect(self, _path): pass
	def recv(self, _size): response, self.response = self.response, b""; return response
	def sendall(self, _data):
		if self.send_error is not None: raise self.send_error


def test_sanitize_response_wait_does_not_use_short_operation_timeout(monkeypatch):
	client_socket = FakeSocket(response=b'{"result":{"final_status":"INCONCLUSIVE"}}\n')
	monkeypatch.setattr("local_agent.privileged_executor.socket.AF_UNIX", 1, raising=False)
	monkeypatch.setattr("local_agent.privileged_executor.socket.socket", lambda *_args: client_socket)
	client = PrivilegedExecutorClient("/run/vyper/executor.sock")
	assert client.sanitize_device("/dev/mock", {"approved": False}, dry_run=True)["final_status"] == "INCONCLUSIVE"
	assert client_socket.timeouts == [30.0, None]


def test_short_executor_request_retains_bounded_timeout(monkeypatch):
	client_socket = FakeSocket()
	monkeypatch.setattr("local_agent.privileged_executor.socket.AF_UNIX", 1, raising=False)
	monkeypatch.setattr("local_agent.privileged_executor.socket.socket", lambda *_args: client_socket)
	assert PrivilegedExecutorClient("/run/vyper/executor.sock").request("discover") == []
	assert client_socket.timeouts == [30.0]


@pytest.mark.parametrize("disconnect", [
	BrokenPipeError(), ConnectionResetError(), ConnectionAbortedError(), OSError(errno.EPIPE, "peer closed"),
])
def test_response_disconnect_is_contained_and_later_delivery_can_continue(disconnect):
	assert _send_response(FakeSocket(send_error=disconnect), {"result": {}}) is False
	assert _send_response(FakeSocket(), {"result": {}}) is True


def test_unrelated_response_socket_error_is_not_hidden():
	with pytest.raises(OSError):
		_send_response(FakeSocket(send_error=OSError(errno.EBADF, "bad descriptor")), {"result": {}})
