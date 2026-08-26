from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuthorizationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: bool = False
    ata_password: str | None = None


class SanitizeJobCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1)
    authorization: AuthorizationInput = Field(default_factory=AuthorizationInput)
    dry_run: bool | None = None


class DeviceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_type: str = "storage"
    device_path: str
    device_type: str
    model: str | None = None
    serial_number: str | None = None
    profile_json: dict[str, Any] = Field(default_factory=dict)
    is_system_device: bool = False
    mounted: bool = False
    mounted_partitions: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime | None = None


class AssetRead(DeviceRead):
    pass


class ResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    execution_json: dict[str, Any] = Field(default_factory=dict)
    verification_json: dict[str, Any] = Field(default_factory=dict)
    evidence_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime | None = None


class CertificateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str | None = None
    certificate_id: str | None = None
    job_id: str
    target: str
    final_status: str
    outcome_kind: str | None = None
    successful_sanitization_claim: bool = False
    certificate_hash: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    certificate_json: dict[str, Any] = Field(default_factory=dict)


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str | None = None
    action: str
    actor: str | None = None
    request_json: dict[str, Any] = Field(default_factory=dict)
    response_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    resource: str | None = None
    request_id: str | None = None
    previous_hash: str | None = None
    event_hash: str | None = None


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class MFACodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=6, max_length=64)


class MFAEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    display_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=256)
    role: str


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str | None = None
    disabled: bool | None = None


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    username: str
    display_name: str
    role: str
    disabled_at: datetime | None = None
    created_at: datetime


class JobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target: str
    dry_run: bool
    job_state: str
    final_status: str
    pathway: str | None = None
    outcome_kind: str | None = None
    successful_sanitization_claim: bool = False
    message: str
    state_history_json: list[str] = Field(default_factory=list)
    authorization_json: dict[str, Any] = Field(default_factory=dict)
    profile_json: dict[str, Any] = Field(default_factory=dict)
    policy_json: dict[str, Any] = Field(default_factory=dict)
    execution_json: dict[str, Any] = Field(default_factory=dict)
    verification_json: dict[str, Any] = Field(default_factory=dict)
    evidence_json: dict[str, Any] = Field(default_factory=dict)
    certificate_json: dict[str, Any] = Field(default_factory=dict)
    certificate_id: str | None = None
    certificate_hash: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    device: DeviceRead
    asset: AssetRead | None = None
    result: ResultRead | None = None
    certificate: CertificateRead | None = None
    audit_logs: list[AuditLogRead] = Field(default_factory=list)


class EnrollmentTokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ttl_seconds: int = Field(default=600, ge=60, le=3600)


class EnrollmentTokenRead(BaseModel):
    token: str
    expires_at: datetime
    single_use: bool = True


class AgentEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enrollment_token: str = Field(min_length=16)
    display_name: str | None = None
    hostname: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    agent_version: str = Field(min_length=1)
    api_version: str = "2"
    agent_protocol_version: str = "1"
    device_public_key_pem: str | None = None
    device_public_key_id: str | None = Field(default=None, min_length=64, max_length=64)
    identity_fingerprint: str | None = Field(default=None, min_length=64, max_length=64)


class AgentEnrollResponse(BaseModel):
    agent_id: str
    agent_token: str
    agent_protocol_version: str = "1"
    command_verification_key_pem: str | None = None
    command_verification_key_id: str | None = None


class AgentHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_version: str
    api_version: str
    agent_protocol_version: str = "1"
    hostname: str
    platform: str
    architecture: str
    local_status: str | None = None
    active_job_count: int = Field(default=0, ge=0)
    current_state: str | None = None
    active_job_id: str | None = None
    connectivity_status: str | None = None
    hardware_status: dict[str, Any] = Field(default_factory=dict)


class InventoryDevice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_path: str
    device_type: str = "UNKNOWN"
    model: str | None = None
    serial_number: str | None = None
    wwn: str | None = None
    nvme_nguid: str | None = None
    nvme_eui64: str | None = None
    size_bytes: int | None = None
    interface: str | None = None
    transport: str | None = None
    rotational: bool | None = None
    mounted: bool = False
    mounted_partitions: list[Any] = Field(default_factory=list)
    is_system_device: bool | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    profile_error: str | None = None
    eligible_for_sanitization: bool = False


class InventoryUpload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_protocol_version: str = "1"
    inventory_version: str
    observed_at: datetime
    devices: list[InventoryDevice]


class CentralJobCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str
    dry_run: bool = True
    central_authorized: bool = False
    destructive_confirmation: str | None = None
    idempotency_key: str = Field(min_length=8, max_length=128)
    expires_in_seconds: int = Field(default=3600, ge=60, le=86400)
    execution_mode: str = Field(default="normal_local", pattern=r"^(normal_local|boot_sanitize)$")


class AgentJobEventUpload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_protocol_version: str = "1"
    local_job_id: str
    sequence: int = Field(ge=1)
    state: str
    timestamp: str
    message: str
    progress: dict[str, Any] | None = None


class AgentJobResultUpload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_protocol_version: str = "1"
    idempotency_key: str
    local_job_id: str
    job_state: str
    final_status: str
    created_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    profile: dict[str, Any] | None = None
    policy: dict[str, Any] | None = None
    execution: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None
    evidence: dict[str, Any] | None = None
    certificate: dict[str, Any] | None = None
    state_history: list[dict[str, Any]] = Field(default_factory=list)
    error: dict[str, Any] | None = None
    boot_context: dict[str, Any] | None = None
