from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuthorizationInput(BaseModel):
	model_config = ConfigDict(extra="forbid")

	approved: bool = False
	ata_password: str | None = None


class SanitizeJobRequest(BaseModel):
	model_config = ConfigDict(extra="forbid")

	target: str = Field(min_length=1)
	authorization: AuthorizationInput = Field(default_factory=AuthorizationInput)
	dry_run: bool | None = None


class LocalJobAccepted(BaseModel):
	model_config = ConfigDict(extra="forbid")

	api_version: str = "2"
	local_job_id: str
	target: str
	job_state: str = "PENDING"
	final_status: str | None = None
	message: str = "Job accepted."


class LocalJobEvent(BaseModel):
	model_config = ConfigDict(extra="forbid")

	sequence: int
	state: str
	timestamp: str
	message: str
	progress: dict[str, Any] | None = None


class MountedPartitionRead(BaseModel):
	model_config = ConfigDict(extra="forbid")

	path: str | None = None
	mountpoint: str | None = None


class DiscoveredDeviceRead(BaseModel):
	model_config = ConfigDict(extra="forbid")

	device_path: str
	device_type: str = "UNKNOWN"
	model: str | None = None
	serial_number: str | None = None
	size_bytes: int | None = None
	interface: str | None = None
	transport: str | None = None
	rotational: bool | None = None
	mounted: bool = False
	mounted_partitions: list[MountedPartitionRead] = Field(default_factory=list)
	is_system_device: bool | None = None
	capabilities: dict[str, Any] = Field(default_factory=dict)
	warnings: list[str] = Field(default_factory=list)
	profile_error: str | None = None
	eligible_for_sanitization: bool = False


class LocalJobResponse(BaseModel):
	model_config = ConfigDict(extra="forbid")

	api_version: str = "2"
	local_job_id: str
	target: str
	dry_run: bool
	job_state: str
	final_status: str | None = None
	created_at: str
	started_at: str | None = None
	finished_at: str | None = None
	updated_at: str
	progress: dict[str, Any] | None = None
	profile: dict[str, Any] | None = None
	policy: dict[str, Any] | None = None
	execution: dict[str, Any] | None = None
	verification: dict[str, Any] | None = None
	evidence: dict[str, Any] | None = None
	certificate: dict[str, Any] | None = None
	state_history: list[LocalJobEvent] = Field(default_factory=list)
	error: dict[str, Any] | None = None
	worker_pid: int | None = None
	message: str = ""


class SyncEnrollmentRequest(BaseModel):
	model_config = ConfigDict(extra="forbid")
	enrollment_token: str = Field(min_length=16)
	display_name: str | None = None


class RemoteJobApproval(BaseModel):
	model_config = ConfigDict(extra="forbid")
	approved: bool
	ata_password: str | None = None
