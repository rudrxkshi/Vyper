from __future__ import annotations

import multiprocessing
import os
import threading
from pathlib import Path
from typing import Any

from agent.agent import VYPERAgent

from .jobs import LocalJobWorker, log_job
from .storage import ACTIVE_STATES, LocalJobStore


def _run_native_job(database_path: str, local_job_id: str, target: str, authorization: dict[str, Any], dry_run: bool,
	force_executor_dry_run: bool) -> None:
	"""Fixed child entry point. No command strings or shell input cross this boundary."""
	store = LocalJobStore(database_path)
	effective_dry_run = bool(dry_run) or bool(force_executor_dry_run)
	agent = VYPERAgent(dry_run=effective_dry_run)
	LocalJobWorker(store=store, agent=agent).run(local_job_id, target, authorization, effective_dry_run)


class ProcessJobExecutor:
	"""Supervises one isolated native process per job while SQLite owns target locks."""

	def __init__(self, database_path: str | Path, *, max_workers: int = 2) -> None:
		self.database_path = str(database_path)
		self.max_workers = max(1, int(max_workers))
		self._context = multiprocessing.get_context("spawn")
		self._semaphore = threading.BoundedSemaphore(self.max_workers)
		self._processes: set[multiprocessing.Process] = set()
		self._lock = threading.Lock()

	def submit_job(self, local_job_id: str, target: str, authorization: dict[str, Any], dry_run: bool) -> None:
		if not self._semaphore.acquire(blocking=False):
			raise RuntimeError("Native worker capacity is exhausted.")
		force_dry_run = os.getenv("VYPER_EXECUTOR_DRY_RUN", "true").lower() in {"1", "true", "yes"}
		process = self._context.Process(target=_run_native_job,
			args=(self.database_path, local_job_id, target, dict(authorization), dry_run, force_dry_run),
			name=f"vyper-native-{local_job_id[:8]}", daemon=False)
		try:
			process.start()
		except Exception:
			self._semaphore.release()
			raise
		with self._lock:
			self._processes.add(process)
		threading.Thread(target=self._monitor, args=(process, local_job_id, target), daemon=True,
			name=f"vyper-monitor-{local_job_id[:8]}").start()

	def _monitor(self, process: multiprocessing.Process, local_job_id: str, target: str) -> None:
		process.join()
		try:
			self._handle_exit(local_job_id, target, process.pid, process.exitcode)
		finally:
			with self._lock:
				self._processes.discard(process)
			self._semaphore.release()

	def _handle_exit(self, local_job_id: str, target: str, pid: int | None, exit_code: int | None) -> None:
		store = LocalJobStore(self.database_path)
		job = store.get_job(local_job_id)
		if job is not None and job["job_state"] in ACTIVE_STATES:
			store.complete(local_job_id, {
				"job_state": "INCONCLUSIVE", "final_status": "INCONCLUSIVE",
				"message": "Native worker exited before terminal verification was recorded.", "progress": job.get("progress"),
				"profile": job.get("profile"), "policy": job.get("policy"), "execution": job.get("execution"),
				"verification": None, "evidence": None, "certificate": None,
				"error": {"code": "WORKER_EXIT", "message": "Native worker exited unexpectedly.", "exit_code": exit_code},
			})
		log_job("worker_exit", local_job_id=local_job_id, target=target, worker_pid=pid,
			worker_exit_code=exit_code, job_state=(store.get_job(local_job_id) or {}).get("job_state"))

	def shutdown(self, *, wait: bool = False) -> None:
		if wait:
			with self._lock:
				processes = list(self._processes)
			for process in processes:
				process.join()
