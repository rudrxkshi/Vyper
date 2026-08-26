from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from agent.command_runner import CommandExecutor, SubprocessCommandExecutor
from agent.profiler import DeviceProfiler


_NAMESPACE_RE = re.compile(r"nvme\d+(?:c\d+)?n\d+")
_CONTROLLER_RE = re.compile(r"nvme\d+")
_UNSAFE_TYPES = {"crypt", "dm", "lvm", "md", "mpath", "raid", "raid0", "raid1", "raid5", "raid6", "raid10"}


class NVMeControllerResolver:
    """Resolve and safety-check namespace/controller scope without guessing."""

    def __init__(
        self,
        *,
        profiler: DeviceProfiler | None = None,
        command_executor: CommandExecutor | None = None,
        sysfs_root: str | Path = "/sys",
        dev_root: str | Path = "/dev",
        device_exists: Callable[[Path], bool] | None = None,
    ) -> None:
        self.command_executor = command_executor or SubprocessCommandExecutor()
        self.profiler = profiler or DeviceProfiler(command_executor=self.command_executor, sysfs_root=str(sysfs_root))
        self.sysfs_root = Path(sysfs_root)
        self.dev_root = Path(dev_root)
        self.device_exists = device_exists or (lambda path: path.exists() and path.is_char_device())

    def resolve(self, namespace: str) -> dict[str, Any]:
        requested = str(namespace or "").strip()
        name = Path(requested).name
        blockers: list[str] = []
        if not requested.startswith("/dev/") or _NAMESPACE_RE.fullmatch(name) is None:
            return self._result(requested, blockers=["An explicit whole NVMe namespace is required."])

        block_root = self.sysfs_root / "class" / "block"
        namespace_link = block_root / name
        try:
            namespace_real = (namespace_link / "device").resolve(strict=True)
        except OSError:
            return self._result(requested, blockers=["NVMe namespace sysfs topology is unavailable."])

        controllers = sorted({part for part in namespace_real.parts if _CONTROLLER_RE.fullmatch(part)})
        if not controllers:
            try:
                marker = (namespace_link / "device" / "controller").read_text(encoding="utf-8").strip()
            except OSError:
                marker = ""
            controllers = [marker] if _CONTROLLER_RE.fullmatch(marker) else []
        if len(controllers) != 1:
            return self._result(requested, blockers=["NVMe namespace/controller relation is ambiguous."])
        controller_name = controllers[0]
        controller_sysfs = self.sysfs_root / "class" / "nvme" / controller_name
        controller_path = str(self.dev_root / controller_name).replace("\\", "/")
        if not controller_sysfs.exists() or not self.device_exists(self.dev_root / controller_name):
            return self._result(requested, controller=controller_path, blockers=["Resolved NVMe controller is unavailable."])

        namespaces: list[str] = []
        try:
            entries = list(block_root.iterdir())
        except OSError:
            entries = []
        for entry in entries:
            if _NAMESPACE_RE.fullmatch(entry.name) is None:
                continue
            try:
                real = (entry / "device").resolve(strict=True)
            except OSError:
                continue
            try:
                entry_marker = (entry / "device" / "controller").read_text(encoding="utf-8").strip()
            except OSError:
                entry_marker = ""
            if controller_name in real.parts or entry_marker == controller_name:
                namespaces.append(str(self.dev_root / entry.name).replace("\\", "/"))
        namespaces = sorted(set(namespaces))
        if requested not in namespaces:
            blockers.append("Selected namespace was not found beneath the resolved controller.")
        if not namespaces:
            blockers.append("No namespaces could be enumerated for the resolved controller.")

        ctrl_result = self.command_executor.run(["nvme", "id-ctrl", controller_path, "--output-format=json"], timeout=30)
        ns_result = self.command_executor.run(["nvme", "id-ns", requested, "--output-format=json"], timeout=30)
        nsid_result = self.command_executor.run(["nvme", "get-ns-id", requested], timeout=30)
        controller_identify = self._json(ctrl_result.stdout) if ctrl_result.success else {}
        namespace_identify = self._json(ns_result.stdout) if ns_result.success else {}
        if not ctrl_result.success or not controller_identify:
            blockers.append("Controller-scoped NVMe identify data is unavailable.")
        if not ns_result.success or not namespace_identify:
            blockers.append("Namespace identify data is unavailable.")
        nsid_match = re.search(r"(\d+)", nsid_result.stdout or "") if nsid_result.success else None
        namespace_id = int(nsid_match.group(1)) if nsid_match else None
        if namespace_id is None:
            blockers.append("NVMe namespace ID is unavailable.")

        namespace_safety: list[dict[str, Any]] = []
        for item in namespaces:
            safety = self._namespace_safety(item)
            namespace_safety.append(safety)
            if safety["safe"] is not True:
                blockers.append(f"Namespace {item} safety is not proven: {safety['reason']}")
        selected_safety = next((item for item in namespace_safety if item.get("namespace") == requested), {})
        for label, profiled, identified in (
            ("controller serial", selected_safety.get("serial_number"), controller_identify.get("sn")),
            ("controller model", selected_safety.get("model"), controller_identify.get("mn")),
            ("namespace NGUID", selected_safety.get("nguid"), namespace_identify.get("nguid")),
            ("namespace EUI-64", selected_safety.get("eui64"), namespace_identify.get("eui64") or namespace_identify.get("eui")),
        ):
            if profiled and identified and self._identity_token(profiled) != self._identity_token(identified):
                blockers.append(f"{label} differs between profile and identify data.")
        if len(namespaces) > 1:
            blockers.append(
                "NVMe Sanitize operates at controller scope. This controller exposes multiple namespaces; "
                "destructive execution is blocked until controller-wide impact is explicitly supported."
            )

        return self._result(
            requested,
            controller=controller_path,
            namespaces=namespaces,
            blockers=blockers,
            namespace_real=str(namespace_real),
            controller_identify=controller_identify,
            namespace_identify=namespace_identify,
            namespace_id=namespace_id,
            controller_identity={
                "path": controller_path,
                "serial_number": controller_identify.get("sn"),
                "model": controller_identify.get("mn"),
                "firmware_revision": controller_identify.get("fr"),
                "pci_controller_identity": str(namespace_real),
            },
            pci_controller_identity=str(namespace_real),
            controller_sanicap=self._sanicap(controller_identify.get("sanicap")),
            namespace_safety=namespace_safety,
            controller_reachable=ctrl_result.success,
            topology_known=True,
            active_holders=[item["namespace"] for item in namespace_safety if item.get("safe") is not True],
        )

    def _namespace_safety(self, namespace: str) -> dict[str, Any]:
        try:
            profile = self.profiler.profile(namespace)
        except Exception as exc:
            return {"namespace": namespace, "safe": False, "reason": f"profiling failed: {type(exc).__name__}"}
        if profile.errors or profile.device_type != "NVMe":
            return {"namespace": namespace, "safe": False, "reason": "classification or profile state is unknown"}
        if profile.is_system_device:
            return {"namespace": namespace, "safe": False, "reason": "system-associated"}
        if profile.mounted:
            return {"namespace": namespace, "safe": False, "reason": "mounted"}
        result = self.command_executor.run(
            ["lsblk", "--json", "--inverse", "--output", "NAME,PATH,TYPE,FSTYPE,MOUNTPOINTS", namespace], timeout=30
        )
        if not result.success:
            return {"namespace": namespace, "safe": False, "reason": "holder/swap topology is unknown"}
        payload = self._json(result.stdout)
        nodes = list(payload.get("blockdevices") or [])
        while nodes:
            node = nodes.pop()
            if not isinstance(node, dict):
                return {"namespace": namespace, "safe": False, "reason": "malformed topology"}
            node_type = str(node.get("type") or "").lower()
            if node_type in _UNSAFE_TYPES or str(node.get("fstype") or "").lower() == "swap":
                return {"namespace": namespace, "safe": False, "reason": f"active {node_type or 'swap'} dependency"}
            if any(node.get("mountpoints") or []):
                return {"namespace": namespace, "safe": False, "reason": "mounted topology entry"}
            nodes.extend(node.get("children") or [])
        capabilities = profile.capabilities or {}
        return {
            "namespace": namespace, "safe": True, "reason": "read-only checks passed",
            "serial_number": profile.serial_number, "model": profile.model,
            "size_bytes": profile.size_bytes, "nguid": capabilities.get("nvme_nguid"),
            "eui64": capabilities.get("nvme_eui64"),
        }

    def _result(self, requested: str, *, controller: str | None = None, namespaces: list[str] | None = None,
        blockers: list[str], **extra: Any) -> dict[str, Any]:
        namespaces = list(namespaces or [])
        proven = bool(controller and requested in namespaces and not blockers)
        return {
            "requested_namespace": requested,
            "resolved_controller": controller,
            "controller_path": controller,
            "sanitize_target": controller if proven else None,
            "sanitize_scope": "controller",
            "controller_namespaces": namespaces,
            "scope_proven": proven,
            "execution_eligible": proven,
            "execution_blockers": list(blockers),
            **extra,
        }

    def _json(self, output: str) -> dict[str, Any]:
        try:
            payload = json.loads(output or "{}")
        except (TypeError, ValueError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _sanicap(self, raw: Any) -> dict[str, Any]:
        try:
            bits = int(str(raw), 0)
        except (TypeError, ValueError):
            return {"raw": raw, "crypto_erase": False, "block_erase": False, "overwrite": False}
        return {
            "raw": raw,
            "crypto_erase": bool(bits & 0x1),
            "block_erase": bool(bits & 0x2),
            "overwrite": bool(bits & 0x4),
        }

    def _identity_token(self, value: Any) -> str:
        return re.sub(r"[^a-z0-9]", "", str(value or "").strip().lower())
