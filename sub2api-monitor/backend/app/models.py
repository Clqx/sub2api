from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
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
    DELIVERING = "delivering"
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
    priority: Mapped[int | None] = mapped_column(Integer)
    rate_multiplier: Mapped[float | None] = mapped_column(Float)
    upstream_billing_probe_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    upstream_billing_rate_sync_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    upstream_billing_probe: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    routing_desired_priority: Mapped[int | None] = mapped_column(Integer)
    routing_status: Mapped[str | None] = mapped_column(String(30))
    routing_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    routing_applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rate_limit_reset_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    overload_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    temp_unschedulable_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_observation_id: Mapped[str | None] = mapped_column(String(36))
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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
    channel_failure_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    native_alerts_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    collection_failure_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    ttft_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ttft_percentile: Mapped[str] = mapped_column(
        String(10), default="p95", nullable=False
    )
    ttft_min_samples: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    ttft_warning_ms: Mapped[int] = mapped_column(Integer, default=3000, nullable=False)
    ttft_critical_ms: Mapped[int] = mapped_column(Integer, default=6000, nullable=False)
    ttft_recovery_ms: Mapped[int] = mapped_column(Integer, default=2500, nullable=False)
    quota_warning_remaining: Mapped[float] = mapped_column(Float, default=20.0)
    quota_critical_remaining: Mapped[float] = mapped_column(Float, default=5.0)
    quota_recovery_remaining: Mapped[float] = mapped_column(Float, default=30.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ChannelMonitorCurrent(Base):
    __tablename__ = "channel_monitors"
    __table_args__ = (
        UniqueConstraint("target_id", "external_monitor_id", name="uq_channel_target_external"),
        Index("ix_channel_target_status", "target_id", "primary_status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    external_monitor_id: Mapped[str] = mapped_column(String(160), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    api_mode: Mapped[str] = mapped_column(String(30), default="chat_completions", nullable=False)
    endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    api_key_masked: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    api_key_decrypt_failed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    primary_model: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    extra_models: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    group_name: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    jitter_seconds: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    primary_status: Mapped[str] = mapped_column(String(30), default="", nullable=False)
    primary_latency_ms: Mapped[int | None] = mapped_column(Integer)
    availability_7d: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    extra_models_status: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    template_id: Mapped[str | None] = mapped_column(String(160))
    extra_headers: Mapped[dict[str, str]] = mapped_column(JSON, default=dict, nullable=False)
    body_override_mode: Mapped[str] = mapped_column(String(20), default="off", nullable=False)
    body_override: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    source_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


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
    kind: Mapped[str] = mapped_column(String(20), default="ntfy", nullable=False)
    server_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    topic: Mapped[str] = mapped_column(String(256), default="", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    event_types: Mapped[list[str]] = mapped_column(
        JSON,
        default=lambda: [
            "incident.firing",
            "incident.escalated",
            "incident.resolved",
            "routing.account_switched",
            "routing.rate_recovered",
        ],
        nullable=False,
    )
    severities: Mapped[list[str]] = mapped_column(
        JSON, default=lambda: ["warning", "critical"], nullable=False
    )
    token_ciphertext: Mapped[str | None] = mapped_column(Text)
    signing_secret_ciphertext: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotificationOutbox(Base):
    __tablename__ = "notification_outbox"
    __table_args__ = (
        UniqueConstraint("transition_id", "channel_id", name="uq_outbox_transition_channel"),
        Index("ix_outbox_due", "status", "next_attempt_at"),
        Index("ix_outbox_claim", "status", "lease_expires_at", "next_attempt_at"),
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
    lease_owner: Mapped[str | None] = mapped_column(String(160))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AutomationRule(Base):
    __tablename__ = "automation_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    trigger_rule_key: Mapped[str] = mapped_column(
        String(100), default="account.unavailable", nullable=False
    )
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), default="recommend", nullable=False)
    reason_filters: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    reason_match_mode: Mapped[str] = mapped_column(String(10), default="any", nullable=False)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=900, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AutomationExecution(Base):
    __tablename__ = "automation_executions"
    __table_args__ = (
        UniqueConstraint("rule_id", "transition_id", name="uq_automation_rule_transition"),
        Index("ix_automation_due", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    rule_id: Mapped[str | None] = mapped_column(
        ForeignKey("automation_rules.id", ondelete="SET NULL"), index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    transition_id: Mapped[str] = mapped_column(String(36), nullable=False)
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True
    )
    external_account_id: Mapped[str] = mapped_column(String(160), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(500))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CostRoutingPolicy(Base):
    __tablename__ = "cost_routing_policies"
    __table_args__ = (
        UniqueConstraint("target_id", name="uq_cost_routing_policy_target"),
        Index("ix_cost_routing_due", "enabled", "next_run_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mode: Mapped[str] = mapped_column(String(20), default="recommend", nullable=False)
    probe_interval_seconds: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    priority_scale: Mapped[int] = mapped_column(Integer, default=1000, nullable=False)
    unhealthy_priority: Mapped[int] = mapped_column(Integer, default=100000, nullable=False)
    minimum_priority: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    quality_bindings: Mapped[dict[str, list[str]]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    fallback_account_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    fallback_priorities: Mapped[dict[str, int]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))
    last_account_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_change_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(String(100))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class RoutingDecision(Base):
    __tablename__ = "routing_decisions"
    __table_args__ = (
        Index("ix_routing_decision_target_time", "target_id", "created_at"),
        Index(
            "ix_routing_decision_account_time",
            "target_id",
            "external_account_id",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    policy_id: Mapped[str | None] = mapped_column(
        ForeignKey("cost_routing_policies.id", ondelete="SET NULL"), index=True
    )
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True
    )
    external_account_id: Mapped[str] = mapped_column(String(160), nullable=False)
    account_name: Mapped[str] = mapped_column(String(160), nullable=False)
    observed_multiplier: Mapped[float | None] = mapped_column(Float)
    previous_priority: Mapped[int | None] = mapped_column(Integer)
    desired_priority: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(String(40), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RoutingSessionState(Base):
    __tablename__ = "routing_session_states"
    __table_args__ = (
        UniqueConstraint("target_id", "session_id", name="uq_routing_session_target_session"),
        Index("ix_routing_session_state_updated", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    session_id: Mapped[str] = mapped_column(String(160), nullable=False)
    external_account_id: Mapped[str] = mapped_column(String(160), nullable=False)
    account_name: Mapped[str] = mapped_column(String(160), nullable=False)
    last_usage_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


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
