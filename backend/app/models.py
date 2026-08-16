from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Text, func
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
	created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

	job: Mapped[JobRecord | None] = relationship(back_populates="audit_logs")


DeviceRecord = AssetRecord
SanitizationJobRecord = JobRecord
