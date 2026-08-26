from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.command_runner import CommandResult
from agent.nvme_scope import NVMeControllerResolver
from agent.profiler import DeviceProfile


class ProfileStub:
    def __init__(self, states=None):
        self.states = states or {}

    def profile(self, namespace):
        values = self.states.get(namespace, {})
        return DeviceProfile(
            device_path=namespace, device_type="NVMe", serial_number="SERIAL",
            model="MODEL", size_bytes=1024, is_system_device=values.get("system", False),
            mounted=values.get("mounted", False), errors=values.get("errors", []),
            capabilities=values.get("capabilities", {}),
        )


class ExecutorStub:
    def __init__(self, *, topology_success=True, topology=None, controller_serial="SERIAL", nguid="a" * 32):
        self.topology_success = topology_success
        self.topology = topology or {"blockdevices": [{"name": "namespace", "type": "disk", "fstype": None, "mountpoints": []}]}
        self.calls = []
        self.controller_serial = controller_serial
        self.nguid = nguid

    def run(self, command, timeout=None, cwd=None):
        self.calls.append(list(command))
        if command[:2] == ["nvme", "id-ctrl"]:
            return self.result(command, stdout=json.dumps({"mn": "MODEL", "sn": self.controller_serial, "fr": "1.0", "sanicap": 7}))
        if command[:2] == ["nvme", "id-ns"]:
            return self.result(command, stdout=json.dumps({"nguid": self.nguid, "eui64": "b" * 16}))
        if command[:2] == ["nvme", "get-ns-id"]:
            return self.result(command, stdout="3\n")
        if command[0] == "lsblk":
            return self.result(command, success=self.topology_success, exit_code=0 if self.topology_success else 1,
                stdout=json.dumps(self.topology) if self.topology_success else "")
        raise AssertionError(command)

    def result(self, command, *, success=True, exit_code=0, stdout=""):
        return CommandResult(command=command, success=success, exit_code=exit_code, stdout=stdout, stderr="")


def topology(tmp_path: Path, controller: str, namespaces: list[str], *, selected: str | None = None):
    sysfs = tmp_path / "sys"
    (sysfs / "class" / "nvme" / controller).mkdir(parents=True)
    for namespace in namespaces:
        device = sysfs / "class" / "block" / namespace / "device"
        device.mkdir(parents=True)
        (device / "controller").write_text(controller + "\n", encoding="utf-8")
    selected = selected or namespaces[0]
    return sysfs, f"/dev/{selected}"


def resolver(tmp_path, controller, namespaces, *, states=None, selected=None, executor=None):
    sysfs, requested = topology(tmp_path, controller, namespaces, selected=selected)
    instance = NVMeControllerResolver(
        profiler=ProfileStub(states), command_executor=executor or ExecutorStub(),
        sysfs_root=sysfs, device_exists=lambda path: path == Path(f"/dev/{controller}"),
    )
    return instance, requested


@pytest.mark.parametrize(("controller", "namespace"), [("nvme0", "nvme0n1"), ("nvme12", "nvme12n3")])
def test_namespace_resolves_to_topology_controller(tmp_path, controller, namespace):
    instance, requested = resolver(tmp_path, controller, [namespace])
    scope = instance.resolve(requested)
    assert scope["resolved_controller"] == f"/dev/{controller}"
    assert scope["sanitize_target"] == f"/dev/{controller}"
    assert scope["controller_namespaces"] == [requested]
    assert scope["execution_eligible"] is True


def test_ambiguous_relation_is_rejected(tmp_path):
    sysfs = tmp_path / "sys"
    device = sysfs / "class" / "block" / "nvme0n1" / "device"
    device.mkdir(parents=True)
    (device / "controller").write_text("nvme0,nvme1", encoding="utf-8")
    instance = NVMeControllerResolver(profiler=ProfileStub(), command_executor=ExecutorStub(), sysfs_root=sysfs)
    assert "ambiguous" in instance.resolve("/dev/nvme0n1")["execution_blockers"][0]


def test_missing_controller_is_rejected(tmp_path):
    sysfs = tmp_path / "sys"
    device = sysfs / "class" / "block" / "nvme0n1" / "device"
    device.mkdir(parents=True)
    (device / "controller").write_text("nvme0", encoding="utf-8")
    instance = NVMeControllerResolver(profiler=ProfileStub(), command_executor=ExecutorStub(), sysfs_root=sysfs)
    assert "unavailable" in instance.resolve("/dev/nvme0n1")["execution_blockers"][0]


def test_multiple_namespaces_are_blocked_even_when_individually_safe(tmp_path):
    instance, requested = resolver(tmp_path, "nvme0", ["nvme0n1", "nvme0n2"])
    scope = instance.resolve(requested)
    assert scope["execution_eligible"] is False
    assert any("multiple namespaces" in item for item in scope["execution_blockers"])


@pytest.mark.parametrize(("states", "reason"), [
    ({"/dev/nvme0n2": {"mounted": True}}, "mounted"),
    ({"/dev/nvme0n2": {"system": True}}, "system-associated"),
])
def test_another_unsafe_namespace_is_reported(tmp_path, states, reason):
    instance, requested = resolver(tmp_path, "nvme0", ["nvme0n1", "nvme0n2"], states=states)
    scope = instance.resolve(requested)
    assert any(reason in item for item in scope["execution_blockers"])


def test_unknown_namespace_safety_is_blocked(tmp_path):
    instance, requested = resolver(tmp_path, "nvme0", ["nvme0n1"], executor=ExecutorStub(topology_success=False))
    scope = instance.resolve(requested)
    assert scope["execution_eligible"] is False
    assert any("unknown" in item for item in scope["execution_blockers"])


def test_controller_identity_mismatch_is_blocked(tmp_path):
    instance, requested = resolver(tmp_path, "nvme0", ["nvme0n1"],
        executor=ExecutorStub(controller_serial="OTHER"))
    scope = instance.resolve(requested)
    assert scope["execution_eligible"] is False
    assert any("controller serial differs" in item for item in scope["execution_blockers"])


def test_namespace_identity_mismatch_is_blocked(tmp_path):
    states = {"/dev/nvme0n1": {"capabilities": {"nvme_nguid": "f" * 32}}}
    instance, requested = resolver(tmp_path, "nvme0", ["nvme0n1"], states=states)
    scope = instance.resolve(requested)
    assert scope["execution_eligible"] is False
    assert any("namespace NGUID differs" in item for item in scope["execution_blockers"])
