from __future__ import annotations

import inspect
import json
import logging
import os
from dataclasses import fields, is_dataclass
from typing import Any

from fastapi.encoders import jsonable_encoder

from .storage import LocalJobStore, TERMINAL_STATES


logger = logging.getLogger("vyper.local_agent")
_SECRET_MARKERS = ("password", "secret", "token", "credential", "passphrase", "authorization")
_STATE_MESSAGES = {
	"PROFILING": "Profiling target device.",
	"POLICY_SELECTED": "Sanitization policy selected.",
	"AWAITING_AUTHORIZATION": "Awaiting authorization.",
	"RUNNING": "Sanitization pathway is running.",
	"VERIFYING": "Verifying sanitization result.",
	"VERIFIED": "Sanitization result verified.",
	"FAILED": "Sanitization workflow failed.",
	"INCONCLUSIVE": "Sanitization outcome is inconclusive.",
	"UNSUPPORTED": "Sanitization pathway is unsupported.",
	"CANCELLED": "Sanitization job was cancelled.",
}
_PIPELINE_STAGE_MESSAGES = {
	"STAGE_PROFILING_STARTED": "Pipeline stage started: Profiling.",
	"STAGE_PROFILING_COMPLETED": "Pipeline stage completed: Profiling.",
	"STAGE_PROFILING_FAILED": "Pipeline stage failed: Profiling.",
	"STAGE_POLICY_STARTED": "Pipeline stage started: Policy.",
	"STAGE_POLICY_COMPLETED": "Pipeline stage completed: Policy.",
	"STAGE_POLICY_FAILED": "Pipeline stage failed: Policy.",
	"STAGE_EXECUTION_STARTED": "Pipeline stage started: Execution.",
	"STAGE_EXECUTION_COMPLETED": "Pipeline stage completed: Execution.",
	"STAGE_EXECUTION_FAILED": "Pipeline stage failed: Execution.",
	"STAGE_VERIFICATION_STARTED": "Pipeline stage started: Verification.",
	"STAGE_VERIFICATION_COMPLETED": "Pipeline stage completed: Verification.",
	"STAGE_VERIFICATION_FAILED": "Pipeline stage failed: Verification.",
	"STAGE_EVIDENCE_STARTED": "Pipeline stage started: Evidence.",
	"STAGE_EVIDENCE_COMPLETED": "Pipeline stage completed: Evidence.",
	"STAGE_EVIDENCE_FAILED": "Pipeline stage failed: Evidence.",
	"STAGE_CERTIFICATE_STARTED": "Pipeline stage started: Certificate.",
	"STAGE_CERTIFICATE_COMPLETED": "Pipeline stage completed: Certificate.",
	"STAGE_CERTIFICATE_FAILED": "Pipeline stage failed: Certificate.",
}


def redact(value: Any, secrets: tuple[str, ...] = ()) -> Any:
	if isinstance(value, dict):
		return {
			str(key): "<redacted>"
			if any(marker in str(key).lower() for marker in _SECRET_MARKERS)
			else redact(item, secrets)
			for key, item in value.items()
		}
	if isinstance(value, (list, tuple)):
		return [redact(item, secrets) for item in value]
	if isinstance(value, str):
		redacted = value
		for secret in secrets:
			if secret:
				redacted = redacted.replace(secret, "<redacted>")
		return redacted
	return value


def result_payload(result: Any, *, secrets: tuple[str, ...] = ()) -> dict[str, Any]:
	if isinstance(result, dict):
		payload = result
	elif is_dataclass(result):
		payload = _plain_value(result)
	else:
		raise TypeError("VYPERAgent returned an unsupported result type.")
	encoded = jsonable_encoder(payload)
	if not isinstance(encoded, dict):
		raise TypeError("VYPERAgent result did not encode to an object.")
	return redact(_terminal_reporting_view(encoded), secrets)


def _terminal_reporting_view(payload: dict[str, Any]) -> dict[str, Any]:
	"""Label raw pathway state and expose a non-contradictory terminal view.

	Pathways may return RUNNING to mean that the command phase completed and is
	ready for verification. That raw evidence is retained, but must not look like
	an active operation once orchestration has reached a terminal state.
	"""
	evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
	terminal = str(evidence.get("final_status") or payload.get("final_status") or payload.get("job_state") or "")
	if terminal not in TERMINAL_STATES:
		return payload
	payload["orchestration_terminal_status"] = terminal
	execution = payload.get("execution")
	if isinstance(execution, dict):
		raw_status = str(execution.get("status") or "")
		execution["raw_status"] = raw_status
		execution["status"] = terminal
		execution["status_scope"] = "orchestration_terminal"
	payload["execution_status_semantics"] = {
		"execution.status": "orchestration_terminal",
		"execution.raw_status": "raw_pathway_historical",
		"evidence.execution.status": "raw_pathway_historical",
		"certificate.execution.status": "raw_pathway_historical",
	}
	return payload


def _plain_value(value: Any) -> Any:
	"""Convert dataclasses and collection subclasses without reconstructing them."""
	if is_dataclass(value) and not isinstance(value, type):
		return {field.name: _plain_value(getattr(value, field.name)) for field in fields(value)}
	if isinstance(value, dict):
		return {key: _plain_value(item) for key, item in value.items()}
	if isinstance(value, (list, tuple, set, frozenset)):
		return [_plain_value(item) for item in value]
	return value


def log_job(event: str, **fields: Any) -> None:
	safe = redact({"event": event, **fields})
	logger.info(json.dumps(safe, sort_keys=True, separators=(",", ":")))


class LocalJobWorker:
	def __init__(self, *, store: LocalJobStore, agent: Any) -> None:
		self.store = store
		self.agent = agent

	def run(self, local_job_id: str, target: str, authorization: dict[str, Any], dry_run: bool) -> None:
		if not self.store.start_job(local_job_id, os.getpid()):
			return
		started = self.store.get_job(local_job_id)
		log_job(
			"worker_started",
			local_job_id=local_job_id,
			target=target,
			job_state="PROFILING",
			event_sequence=started["state_history"][-1]["sequence"],
		)

		try:
			parameters = inspect.signature(self.agent.sanitize_device).parameters
			supports_events = "event_callback" in parameters
			kwargs: dict[str, Any] = {}
			if supports_events:
				kwargs["event_callback"] = lambda state: self._state_event(local_job_id, state)
			if "stage_callback" in parameters:
				kwargs["stage_callback"] = lambda event: self._stage_event(local_job_id, event)
			if "progress_callback" in parameters:
				kwargs["progress_callback"] = lambda progress: self._progress_event(local_job_id, progress)
			result = self.agent.sanitize_device(
				target,
				authorization=authorization,
				dry_run=dry_run,
				**kwargs,
			)
			secret = str(authorization.get("ata_password") or "")
			payload = result_payload(result, secrets=(secret,))
			if not supports_events:
				self._import_state_history(local_job_id, payload.get("state_history") or [])
			terminal = self._terminal_payload(payload, dry_run=dry_run)
			stored = self.store.complete(local_job_id, terminal)
			log_job(
				"terminal_result",
				local_job_id=local_job_id,
				target=target,
				job_state=stored["job_state"],
				event_sequence=stored["state_history"][-1]["sequence"],
			)
		except Exception:
			failure = {
				"job_state": "FAILED",
				"final_status": "FAILED",
				"message": "Local sanitization worker failed.",
				"progress": None,
				"profile": None,
				"policy": None,
				"execution": None,
				"verification": None,
				"evidence": None,
				"certificate": None,
				"error": {"code": "WORKER_FAILURE", "message": "Local sanitization worker failed."},
			}
			stored = self.store.complete(local_job_id, failure)
			log_job(
				"worker_failure",
				local_job_id=local_job_id,
				target=target,
				job_state="FAILED",
				event_sequence=stored["state_history"][-1]["sequence"],
			)
		finally:
			authorization.clear()

	def _state_event(self, local_job_id: str, state: Any) -> None:
		state_text = str(getattr(state, "value", state))
		if state_text in TERMINAL_STATES:
			return
		current = self.store.get_job(local_job_id)
		if current is None or current["job_state"] == state_text:
			return
		progress = {"kind": "indeterminate"} if state_text in {"RUNNING", "VERIFYING"} else None
		stored = self.store.transition(
			local_job_id,
			state_text,
			_STATE_MESSAGES.get(state_text, f"Job entered {state_text}."),
			progress=progress,
		)
		if stored is not None:
			log_job(
				"transition",
				local_job_id=local_job_id,
				target=stored["target"],
				job_state=state_text,
				event_sequence=stored["state_history"][-1]["sequence"],
			)

	def _progress_event(self, local_job_id: str, progress: Any) -> None:
		bytes_completed = progress.get("bytes_written") if isinstance(progress, dict) else getattr(progress, "bytes_written", None)
		bytes_total = progress.get("total_bytes") if isinstance(progress, dict) else getattr(progress, "total_bytes", None)
		if not isinstance(bytes_completed, int) or not isinstance(bytes_total, int) or bytes_total <= 0:
			return
		self.store.update_progress(
			local_job_id,
			{
				"kind": "bytes",
				"bytes_completed": bytes_completed,
				"bytes_total": bytes_total,
			},
		)

	def _stage_event(self, local_job_id: str, event: Any) -> None:
		event_text = str(event)
		message = _PIPELINE_STAGE_MESSAGES.get(event_text)
		if message is None:
			return
		stored = self.store.record_event_once(local_job_id, event_text, message)
		if stored is not None:
			log_job(
				"pipeline_stage",
				local_job_id=local_job_id,
				target=stored["target"],
				stage_event=event_text,
				event_sequence=stored["state_history"][-1]["sequence"],
			)

	def _import_state_history(self, local_job_id: str, states: list[Any]) -> None:
		for state in states:
			state_text = str(getattr(state, "value", state))
			job = self.store.get_job(local_job_id)
			if job is None or state_text == "PENDING" or job["job_state"] == state_text:
				continue
			self._state_event(local_job_id, state_text)

	def _terminal_payload(self, payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
		evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else None
		verification = payload.get("verification") if isinstance(payload.get("verification"), dict) else None
		state = str(payload.get("job_state") or "FAILED")
		final_status = str((evidence or {}).get("final_status") or payload.get("final_status") or state)
		if state in TERMINAL_STATES and final_status in TERMINAL_STATES and state != final_status:
			state = final_status
		verified_claim = (
			state == "VERIFIED"
			and final_status == "VERIFIED"
			and bool((verification or {}).get("verified"))
		)
		if state == "VERIFIED" and not verified_claim:
			state = "INCONCLUSIVE"
			final_status = "INCONCLUSIVE"
			message = "Agent returned VERIFIED without durable verification proof; outcome downgraded."
		else:
			message = str(payload.get("message") or _STATE_MESSAGES.get(state, "Workflow completed."))
		if state not in TERMINAL_STATES:
			state = "INCONCLUSIVE"
			final_status = "INCONCLUSIVE"
			message = "Agent workflow ended without a terminal verified outcome."
		progress = self._final_progress(payload.get("execution"))
		return {
			"job_state": state,
			"final_status": final_status,
			"message": message,
			"progress": progress,
			"profile": payload.get("profile") if isinstance(payload.get("profile"), dict) else None,
			"policy": payload.get("policy") if isinstance(payload.get("policy"), dict) else None,
			"execution": payload.get("execution") if isinstance(payload.get("execution"), dict) else None,
			"verification": verification,
			"evidence": evidence,
			"certificate": payload.get("certificate") if isinstance(payload.get("certificate"), dict) else None,
			"error": None,
		}

	def _final_progress(self, execution: Any) -> dict[str, Any] | None:
		if not isinstance(execution, dict):
			return None
		metadata = execution.get("metadata") if isinstance(execution.get("metadata"), dict) else {}
		completed = metadata.get("bytes_written")
		total = metadata.get("total_bytes")
		if isinstance(completed, int) and isinstance(total, int) and total > 0:
			return {"kind": "bytes", "bytes_completed": completed, "bytes_total": total}
		method = str(metadata.get("method") or metadata.get("sanitize_method") or "")
		if method:
			return {"kind": "indeterminate"}
		return None
