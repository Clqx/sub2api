from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def uuid_str() -> str:
    return str(uuid.uuid4())


class TargetMode(str, enum.Enum):
    API_ONLY = "api_only"
    FULL = "full"


class SupportState(str, enum.Enum):
    UNKNOWN = "unknown"
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"


class RuntimeState(str, enum.Enum):
    HEALTHY = "healthy"
    UNAVAILABLE = "unavailable"
    MISCONFIGURED = "misconfigured"
    DISABLED = "disabled"


class FreshnessState(str, enum.Enum):
    FRESH = "fresh"
    STALE = "stale"
    MISSING = "missing"


class RunStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class IncidentStatus(str, enum.Enum):
    FIRING = "firing"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class OutboxStatus(str, enum.Enum):
    PENDING = "pending"
    SENT = "sent"
    DEAD = "dead"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), default=TargetMode.API_ONLY.value)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    collection_interval_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    labels: Mapped[dict[str, str]] = mapped_column(JSON, default=dict, nullable=False)
    monitoring_readiness: Mapped[str] = mapped_column(String(20), default="not_ready")
    api_connection_state: Mapped[str] = mapped_column(String(30), default="unknown")
    db_connection_state: Mapped[str] = mapped_column(String(30), default="not_configured")
    binding_state: Mapped[str] = mapped_column(String(30), default="not_required")
    binding_method: Mapped[str | None] = mapped_column(String(60))
    binding_confidence: Mapped[str | None] = mapped_column(String(20))
    binding_api_fingerprint: Mapped[str | None] = mapped_column(String(64))
    binding_db_fingerprint: Mapped[str | None] = mapped_column(String(64))
    binding_db_schema_fingerprint: Mapped[str | None] = mapped_column(String(64))
    binding_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    binding_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_probe_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_collection_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    secret: Mapped[TargetSecret | None] = relationship(
        back_populates="target", cascade="all, delete-orphan", uselist=False
    )
    database_secret: Mapped[TargetDatabaseSecret | None] = relationship(
        back_populates="target", cascade="all, delete-orphan", uselist=False
    )
    capabilities: Mapped[list[Capability]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class TargetSecret(Base):
    __tablename__ = "target_secrets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), unique=True, index=True
    )
    auth_type: Mapped[str] = mapped_column(String(30), nullable=False)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), default="primary", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    target: Mapped[Target] = relationship(back_populates="secret")


class TargetDatabaseSecret(Base):
    __tablename__ = "target_database_secrets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), unique=True, index=True
    )
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), default="primary", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    target: Mapped[Target] = relationship(back_populates="database_secret")


class Capability(Base):
    __tablename__ = "target_capabilities"
    __table_args__ = (
        UniqueConstraint("target_id", "key", "scope_type", "scope_id", name="uq_capability_scope"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(100), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(20), default="target", nullable=False)
    scope_id: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    support_state: Mapped[str] = mapped_column(
        String(30), default=SupportState.UNKNOWN.value, nullable=False
    )
    runtime_state: Mapped[str] = mapped_column(
        String(30), default=RuntimeState.DISABLED.value, nullable=False
    )
    freshness: Mapped[str] = mapped_column(
        String(20), default=FreshnessState.MISSING.value, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    source: Mapped[str] = mapped_column(String(40), default="api", nullable=False)
    side_effect: Mapped[str] = mapped_column(String(80), default="none", nullable=False)
    reason: Mapped[str | None] = mapped_column(String(500))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    target: Mapped[Target] = relationship(back_populates="capabilities")


class CollectionRun(Base):
    __tablename__ = "collection_runs"
    __table_args__ = (Index("ix_runs_target_status_created", "target_id", "status", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default=RunStatus.QUEUED.value, index=True)
    trigger: Mapped[str] = mapped_column(String(20), default="manual")
    worker_id: Mapped[str | None] = mapped_column(String(100))
    account_count: Mapped[int] = mapped_column(Integer, default=0)
    quota_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ActiveQuotaAttempt(Base):
    __tablename__ = "active_quota_attempts"
    __table_args__ = (
        Index(
            "ix_active_quota_attempt_target_account_time",
            "target_id",
            "external_account_id",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    correlation_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    run_id: Mapped[str | None] = mapped_column(
        ForeignKey("collection_runs.id", ondelete="SET NULL"), index=True
    )
    external_account_id: Mapped[str] = mapped_column(String(160), nullable=False)
    actor: Mapped[str] = mapped_column(String(160), nullable=False)
    outcome: Mapped[str] = mapped_column(String(30), default="running", index=True)
    before_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    after_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    quota_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CollectorLease(Base):
    __tablename__ = "collector_leases"

    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True
    )
    owner_id: Mapped[str] = mapped_column(String(100), nullable=False)
    lease_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AccountCurrent(Base):
    __tablename__ = "accounts"
    __table_args__ = (
        UniqueConstraint("target_id", "external_account_id", name="uq_account_target_external"),
        Index("ix_accounts_target_available", "target_id", "available"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    external_account_id: Mapped[str] = mapped_column(String(160), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    account_type: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    schedulable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    available: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    availability_reasons: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    group_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rate_limit_reset_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    overload_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    temp_unschedulable_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_observation_id: Mapped[str | None] = mapped_column(String(36))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AccountObservation(Base):
    __tablename__ = "account_observations"
    __table_args__ = (
        UniqueConstraint("producer_id", "batch_id", "sequence", name="uq_observation_replay"),
        Index(
            "ix_observation_target_account_time", "target_id", "external_account_id", "observed_at"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    schema_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    producer_id: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("collection_runs.id", ondelete="CASCADE"))
    batch_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    external_account_id: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), default="account.state")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source: Mapped[str] = mapped_column(String(40), default="sub2api_api")
    freshness: Mapped[str] = mapped_column(String(20), default=FreshnessState.FRESH.value)
    runtime_state: Mapped[str] = mapped_column(String(30), default=RuntimeState.HEALTHY.value)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class QuotaSample(Base):
    __tablename__ = "quota_samples"
    __table_args__ = (
        Index(
            "ix_quota_target_account_key_time",
            "target_id",
            "external_account_id",
            "quota_key",
            "observed_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    external_account_id: Mapped[str] = mapped_column(String(160), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    quota_key: Mapped[str] = mapped_column(String(160), nullable=False)
    label: Mapped[str] = mapped_column(String(160), nullable=False)
    utilization_percent: Mapped[float | None] = mapped_column(Float)
    remaining_percent: Mapped[float | None] = mapped_column(Float)
    used_value: Mapped[float | None] = mapped_column(Float)
    limit_value: Mapped[float | None] = mapped_column(Float)
    remaining_value: Mapped[float | None] = mapped_column(Float)
    unit: Mapped[str] = mapped_column(String(30), nullable=False)
    reset_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    freshness: Mapped[str] = mapped_column(String(20), default=FreshnessState.FRESH.value)
    source_observation_id: Mapped[str | None] = mapped_column(String(36))


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    unavailable_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    quota_warning_remaining: Mapped[float] = mapped_column(Float, default=20.0)
    quota_critical_remaining: Mapped[float] = mapped_column(Float, default=5.0)
    quota_recovery_remaining: Mapped[float] = mapped_column(Float, default=30.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (UniqueConstraint("fingerprint", name="uq_incident_fingerprint"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), index=True
    )
    subject_type: Mapped[str] = mapped_column(String(30), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(160), nullable=False)
    rule_key: Mapped[str] = mapped_column(String(100), nullable=False)
    window_key: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default=IncidentStatus.FIRING.value, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    fired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IncidentTransition(Base):
    __tablename__ = "incident_transitions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    from_status: Mapped[str | None] = mapped_column(String(30))
    to_status: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    server_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    topic: Mapped[str] = mapped_column(String(256), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    token_ciphertext: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotificationOutbox(Base):
    __tablename__ = "notification_outbox"
    __table_args__ = (
        UniqueConstraint("transition_id", "channel_id", name="uq_outbox_transition_channel"),
        Index("ix_outbox_due", "status", "next_attempt_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    transition_id: Mapped[str] = mapped_column(String(36), nullable=False)
    channel_id: Mapped[str] = mapped_column(
        ForeignKey("notification_channels.id", ondelete="CASCADE")
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=OutboxStatus.PENDING.value, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_error: Mapped[str | None] = mapped_column(String(500))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"

    worker_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    actor: Mapped[str] = mapped_column(String(160), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(36), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
