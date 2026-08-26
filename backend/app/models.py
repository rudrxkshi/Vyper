from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, event, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class AssetRecord(Base):
	__tablename__ = "assets"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	asset_type: Mapped[str] = mapped_column(String(64), nullable=False, default="storage")
	device_path: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
	device_type: Mapped[str] = mapped_column(String(64), nullable=False, default="UNKNOWN")
	model: Mapped[str | None] = mapped_column(String(255), nullable=True)
	serial_number: Mapped[str | None] = mapped_column(String(255), nullable=True)
	profile_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	is_system_device: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
	mounted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
	mounted_partitions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
	updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)

	jobs: Mapped[list["JobRecord"]] = relationship(back_populates="asset")


class JobRecord(Base):
	__tablename__ = "jobs"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False, index=True)
	target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
	dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
	job_state: Mapped[str] = mapped_column(String(64), nullable=False)
	final_status: Mapped[str] = mapped_column(String(64), nullable=False)
	pathway: Mapped[str | None] = mapped_column(String(64), nullable=True)
	outcome_kind: Mapped[str | None] = mapped_column(String(64), nullable=True)
	successful_sanitization_claim: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
	message: Mapped[str] = mapped_column(Text, nullable=False, default="")
	state_history_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
	authorization_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	profile_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	policy_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	execution_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	verification_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	certificate_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	certificate_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
	certificate_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
	updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)

	asset: Mapped[AssetRecord] = relationship(back_populates="jobs")
	result: Mapped["ResultRecord | None"] = relationship(back_populates="job", uselist=False)
	certificate: Mapped["CertificateRecord | None"] = relationship(back_populates="job", uselist=False)
	audit_logs: Mapped[list["AuditLogRecord"]] = relationship(back_populates="job")


class ResultRecord(Base):
	__tablename__ = "results"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	job_id: Mapped[str] = mapped_column(String(36), ForeignKey("jobs.id"), unique=True, nullable=False, index=True)
	started_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
	completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
	duration_seconds: Mapped[float | None] = mapped_column(nullable=True)
	execution_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	verification_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
	updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)

	job: Mapped[JobRecord] = relationship(back_populates="result")


class CertificateRecord(Base):
	__tablename__ = "certificates"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	job_id: Mapped[str] = mapped_column(String(36), ForeignKey("jobs.id"), unique=True, nullable=False, index=True)
	certificate_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
	target: Mapped[str] = mapped_column(String(255), nullable=False)
	final_status: Mapped[str] = mapped_column(String(64), nullable=False)
	certificate_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
	outcome_kind: Mapped[str | None] = mapped_column(String(64), nullable=True)
	successful_sanitization_claim: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
	certificate_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
	updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)

	job: Mapped[JobRecord] = relationship(back_populates="certificate")


class AuditLogRecord(Base):
	__tablename__ = "audit_logs"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("jobs.id"), nullable=True, index=True)
	action: Mapped[str] = mapped_column(String(128), nullable=False)
	actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
	request_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	response_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	resource: Mapped[str | None] = mapped_column(String(255), nullable=True)
	request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
	previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
	event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
	organization_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True, index=True)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

	job: Mapped[JobRecord | None] = relationship(back_populates="audit_logs")


DeviceRecord = AssetRecord
SanitizationJobRecord = JobRecord


class UserRecord(Base):
	__tablename__ = "users"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	username: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
	display_name: Mapped[str] = mapped_column(String(255), nullable=False)
	password_hash: Mapped[str] = mapped_column(Text, nullable=False)
	role: Mapped[str] = mapped_column(String(32), nullable=False)
	disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
	updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
	password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
	mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
	mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
	mfa_recovery_codes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class OperatorSessionRecord(Base):
	__tablename__ = "operator_sessions"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
	token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
	expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
	last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
	revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
	absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
	mfa_assurance: Mapped[str] = mapped_column(String(32), nullable=False, default="PASSWORD")
	csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class LoginAttemptRecord(Base):
	__tablename__ = "login_attempts"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	username: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
	remote_address: Mapped[str | None] = mapped_column(String(128), nullable=True)
	succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class AgentRecord(Base):
	__tablename__ = "agents"

	agent_id: Mapped[str] = mapped_column(String(36), primary_key=True)
	display_name: Mapped[str] = mapped_column(String(255), nullable=False)
	hostname: Mapped[str] = mapped_column(String(255), nullable=False)
	platform: Mapped[str] = mapped_column(String(128), nullable=False)
	architecture: Mapped[str] = mapped_column(String(128), nullable=False)
	agent_version: Mapped[str] = mapped_column(String(64), nullable=False)
	api_version: Mapped[str] = mapped_column(String(32), nullable=False)
	agent_protocol_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")
	status: Mapped[str] = mapped_column(String(32), nullable=False, default="OFFLINE")
	last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
	updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
	enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
	revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
	metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
	public_key_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
	public_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
	identity_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
	organization_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True, index=True)


class EnrollmentTokenRecord(Base):
	__tablename__ = "agent_enrollment_tokens"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
	expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
	consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
	consumed_by_agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
	organization_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True, index=True)


class OrganizationRecord(Base):
	__tablename__ = "organizations"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class OrganizationMembershipRecord(Base):
	__tablename__ = "organization_memberships"
	__table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_organization_membership"),)

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False, index=True)
	user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
	role: Mapped[str] = mapped_column(String(32), nullable=False, default="MEMBER")
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RemotePolicyRecord(Base):
	__tablename__ = "remote_policies"
	__table_args__ = (UniqueConstraint("organization_id", "name", name="uq_remote_policy_organization_name"),)

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False, index=True)
	name: Mapped[str] = mapped_column(String(128), nullable=False)
	remote_sanitization_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
	requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
	required_approvals: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
	allow_system_disk: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
	version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
	revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AgentAssetRecord(Base):
	__tablename__ = "agent_assets"
	__table_args__ = (UniqueConstraint("agent_id", "hardware_identity", name="uq_agent_hardware_identity"),)

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.agent_id"), nullable=False, index=True)
	hardware_identity: Mapped[str] = mapped_column(String(64), nullable=False)
	device_path: Mapped[str] = mapped_column(String(255), nullable=False)
	device_type: Mapped[str] = mapped_column(String(64), nullable=False, default="UNKNOWN")
	model: Mapped[str | None] = mapped_column(String(255), nullable=True)
	serial_number: Mapped[str | None] = mapped_column(String(255), nullable=True)
	identity_confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW")
	size_bytes: Mapped[int | None] = mapped_column(nullable=True)
	profile_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	observations_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
	first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
	last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CentralJobRecord(Base):
	__tablename__ = "central_jobs"
	__table_args__ = (UniqueConstraint("agent_id", "idempotency_key", name="uq_agent_job_idempotency"),)

	central_job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
	agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.agent_id"), nullable=False, index=True)
	asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("agent_assets.id"), nullable=False)
	target_identity: Mapped[str] = mapped_column(String(64), nullable=False)
	requested_target: Mapped[str] = mapped_column(String(255), nullable=False)
	requested_by_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
	requested_by: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
	dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False)
	authorization_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	status: Mapped[str] = mapped_column(String(64), nullable=False, default="QUEUED", index=True)
	local_execution_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
	final_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
	progress_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
	claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
	started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
	finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
	updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
	expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
	local_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
	request_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	result_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
	error_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
	idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
	result_idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
	nonce: Mapped[str] = mapped_column(String(64), nullable=False)
	integrity_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
	command_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
	organization_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True, index=True)
	policy_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("remote_policies.id"), nullable=True)
	required_approvals: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class CentralJobApprovalRecord(Base):
	__tablename__ = "central_job_approvals"
	__table_args__ = (UniqueConstraint("central_job_id", "approver_user_id", name="uq_central_job_approver"),)

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	central_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("central_jobs.central_job_id"), nullable=False, index=True)
	approver_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
	approver: Mapped[str] = mapped_column(String(128), nullable=False)
	decision: Mapped[str] = mapped_column(String(32), nullable=False, default="APPROVED")
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SecurityEventRecord(Base):
	__tablename__ = "security_events"

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
	severity: Mapped[str] = mapped_column(String(32), nullable=False, default="INFO")
	actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
	resource: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
	agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
	central_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
	organization_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True, index=True)
	metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CentralJobEventRecord(Base):
	__tablename__ = "central_job_events"
	__table_args__ = (UniqueConstraint("central_job_id", "sequence", name="uq_central_job_event_sequence"),)

	id: Mapped[str] = mapped_column(String(36), primary_key=True)
	central_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("central_jobs.central_job_id"), nullable=False, index=True)
	local_job_id: Mapped[str] = mapped_column(String(36), nullable=False)
	sequence: Mapped[int] = mapped_column(Integer, nullable=False)
	state: Mapped[str] = mapped_column(String(64), nullable=False)
	timestamp: Mapped[str] = mapped_column(String(64), nullable=False)
	message: Mapped[str] = mapped_column(Text, nullable=False)
	progress_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


@event.listens_for(AuditLogRecord, "before_update")
@event.listens_for(AuditLogRecord, "before_delete")
def _audit_records_are_append_only(*_args) -> None:
	raise RuntimeError("Audit records are append-only.")


@event.listens_for(CentralJobApprovalRecord, "before_update")
@event.listens_for(CentralJobApprovalRecord, "before_delete")
def _approval_records_are_append_only(*_args) -> None:
	raise RuntimeError("Approval records are append-only.")
