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