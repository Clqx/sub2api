from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

EventType = Literal["incident.firing", "incident.escalated", "incident.resolved"]
EventSeverity = Literal["info", "warning", "critical"]


def default_event_types() -> list[EventType]:
    return ["incident.firing", "incident.escalated", "incident.resolved"]


def default_event_severities() -> list[EventSeverity]:
    return ["warning", "critical"]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=160)
    password: str = Field(min_length=1, max_length=1024)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class UserResponse(ORMModel):
    id: str
    username: str
    is_admin: bool


class TargetCredential(BaseModel):
    auth_type: Literal["x_api_key", "bearer", "token_pair"]
    api_key: str | None = Field(default=None, min_length=1)
    access_token: str | None = Field(default=None, min_length=1)
    refresh_token: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_secret(self) -> TargetCredential:
        if self.auth_type == "x_api_key" and not self.api_key:
            raise ValueError("api_key is required for x_api_key")
        if self.auth_type in {"bearer", "token_pair"} and not self.access_token:
            raise ValueError("access_token is required for bearer/token_pair")
        if self.auth_type == "token_pair" and not self.refresh_token:
            raise ValueError("refresh_token is required for token_pair")
        return self

    def secret_dict(self) -> dict[str, str]:
        return {
            key: value
            for key, value in {
                "api_key": self.api_key,
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
            }.items()
            if value is not None
        }


class TargetDatabaseCredential(BaseModel):
    database_url: str = Field(min_length=1, max_length=4096)
    ca_certificate: str | None = Field(default=None, min_length=1, max_length=65536)

    @field_validator("ca_certificate")
    @classmethod
    def validate_ca_certificate(cls, value: str | None) -> str | None:
        if value is None:
            return None
        certificate = value.strip()
        if (
            "-----BEGIN CERTIFICATE-----" not in certificate
            or "-----END CERTIFICATE-----" not in certificate
        ):
            raise ValueError("ca_certificate must contain a PEM certificate")
        return certificate + "\n"

    def secret_dict(self) -> dict[str, str]:
        return {
            key: value
            for key, value in {
                "database_url": self.database_url,
                "ca_certificate": self.ca_certificate,
            }.items()
            if value is not None
        }


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    base_url: HttpUrl
    mode: Literal["api_only", "full"] = "api_only"
    enabled: bool = False
    verify_tls: bool = True
    collection_interval_seconds: int = Field(default=60, ge=15, le=86400)
    labels: dict[str, str] = Field(default_factory=dict)
    credential: TargetCredential
    database: TargetDatabaseCredential | None = None

    @model_validator(mode="after")
    def validate_mode_credentials(self) -> TargetCreate:
        if self.mode == "full" and self.database is None:
            raise ValueError("database is required for full mode")
        if self.mode == "api_only" and self.database is not None:
            raise ValueError("database is only accepted in full mode")
        return self


class TargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    base_url: HttpUrl | None = None
    mode: Literal["api_only", "full"] | None = None
    enabled: bool | None = None
    verify_tls: bool | None = None
    collection_interval_seconds: int | None = Field(default=None, ge=15, le=86400)
    labels: dict[str, str] | None = None
    credential: TargetCredential | None = None
    database: TargetDatabaseCredential | None = None


class TargetResponse(ORMModel):
    id: str
    name: str
    base_url: str
    mode: str
    enabled: bool
    verify_tls: bool
    collection_interval_seconds: int
    labels: dict[str, str]
    monitoring_readiness: str
    api_connection_state: str
    db_connection_state: str
    binding_state: str
    binding_method: str | None
    binding_confidence: str | None
    binding_checked_at: datetime | None
    binding_expires_at: datetime | None
    version: str | None
    last_probe_at: datetime | None
    last_collected_at: datetime | None
    next_collection_at: datetime | None
    last_error: str | None
    secret_configured: bool = True
    database_configured: bool = False
    created_at: datetime
    updated_at: datetime


class CapabilityResponse(ORMModel):
    id: str
    target_id: str
    key: str
    scope_type: str
    scope_id: str
    support_state: str
    runtime_state: str
    freshness: str
    enabled: bool
    source: str
    side_effect: str
    reason: str | None
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_error_at: datetime | None


class ActiveRefreshCapabilityUpdate(BaseModel):
    enabled: bool
    confirm_side_effects: bool = False

    @model_validator(mode="after")
    def validate_confirmation(self) -> ActiveRefreshCapabilityUpdate:
        if self.enabled and not self.confirm_side_effects:
            raise ValueError("confirm_side_effects must be true when enabling active refresh")
        return self


class ProbeResponse(BaseModel):
    target: TargetResponse
    capabilities: list[CapabilityResponse]
    account_count: int


class AccountResponse(ORMModel):
    id: str
    target_id: str
    external_account_id: str
    name: str
    platform: str
    account_type: str
    status: str
    schedulable: bool
    available: bool
    availability_reasons: list[str]
    group_ids: list[str]
    priority: int | None
    rate_multiplier: float | None
    upstream_billing_probe_enabled: bool
    upstream_billing_rate_sync_enabled: bool
    upstream_billing_probe: dict[str, Any] | None
    routing_desired_priority: int | None
    routing_status: str | None
    routing_updated_at: datetime | None
    routing_applied_at: datetime | None
    expires_at: datetime | None
    rate_limit_reset_at: datetime | None
    overload_until: datetime | None
    temp_unschedulable_until: datetime | None
    observed_at: datetime
    last_seen_at: datetime
    target_name: str | None = None
    remaining_percent: float | None = None
    quota_freshness: str = "missing"


class AccountCursorPage(BaseModel):
    items: list[AccountResponse]
    next_cursor: str | None = None


class AccountUsageHistory(BaseModel):
    date: str | None = None
    label: str | None = None
    requests: int | None = None
    tokens: int | None = None
    cost: float | None = None
    actual_cost: float | None = None
    user_cost: float | None = None


class AccountUsageDay(BaseModel):
    date: str | None = None
    label: str | None = None
    requests: int | None = None
    tokens: int | None = None
    cost: float | None = None
    user_cost: float | None = None


class AccountUsageSummary(BaseModel):
    days: int | None = None
    actual_days_used: int | None = None
    total_cost: float | None = None
    total_user_cost: float | None = None
    total_standard_cost: float | None = None
    total_requests: int | None = None
    total_tokens: int | None = None
    avg_daily_cost: float | None = None
    avg_daily_user_cost: float | None = None
    avg_daily_requests: float | None = None
    avg_daily_tokens: float | None = None
    avg_duration_ms: float | None = None
    today: AccountUsageDay | None = None
    highest_cost_day: AccountUsageDay | None = None
    highest_request_day: AccountUsageDay | None = None


class AccountModelStat(BaseModel):
    model: str | None = None
    requests: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_creation_tokens: int | None = None
    cache_read_tokens: int | None = None
    total_tokens: int | None = None
    cost: float | None = None
    actual_cost: float | None = None
    account_cost: float | None = None


class AccountEndpointStat(BaseModel):
    endpoint: str | None = None
    requests: int | None = None
    total_tokens: int | None = None
    cost: float | None = None
    actual_cost: float | None = None


class AccountUsageStatsResponse(BaseModel):
    history: list[AccountUsageHistory]
    summary: AccountUsageSummary
    models: list[AccountModelStat]
    endpoints: list[AccountEndpointStat]
    upstream_endpoints: list[AccountEndpointStat]


class QuotaResponse(ORMModel):
    id: str
    target_id: str
    external_account_id: str
    provider: str
    quota_key: str
    label: str
    utilization_percent: float | None
    remaining_percent: float | None
    used_value: float | None
    limit_value: float | None
    remaining_value: float | None
    unit: str
    reset_at: datetime | None
    observed_at: datetime
    source: str
    freshness: str


class RunResponse(ORMModel):
    id: str
    target_id: str
    status: str
    trigger: str
    worker_id: str | None
    account_count: int
    quota_count: int
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    target_id: str | None = None
    enabled: bool = True
    unavailable_enabled: bool = True
    channel_failure_enabled: bool = True
    native_alerts_enabled: bool = True
    collection_failure_enabled: bool = True
    quota_warning_remaining: float = Field(default=20, ge=0, le=100)
    quota_critical_remaining: float = Field(default=5, ge=0, le=100)
    quota_recovery_remaining: float = Field(default=30, ge=0, le=100)

    @model_validator(mode="after")
    def validate_thresholds(self) -> PolicyCreate:
        if self.quota_critical_remaining > self.quota_warning_remaining:
            raise ValueError("critical threshold must not exceed warning")
        if self.quota_recovery_remaining <= self.quota_warning_remaining:
            raise ValueError("recovery threshold must exceed warning")
        return self


class PolicyResponse(ORMModel):
    id: str
    target_id: str | None
    name: str
    enabled: bool
    unavailable_enabled: bool
    channel_failure_enabled: bool
    native_alerts_enabled: bool
    collection_failure_enabled: bool
    quota_warning_remaining: float
    quota_critical_remaining: float
    quota_recovery_remaining: float
    created_at: datetime
    updated_at: datetime


class IncidentResponse(ORMModel):
    id: str
    target_id: str
    policy_id: str
    subject_type: str
    subject_id: str
    rule_key: str
    window_key: str
    status: str
    severity: str
    title: str
    message: str
    fired_at: datetime
    updated_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None


class ChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    kind: Literal["ntfy", "webhook"] = "ntfy"
    server_url: HttpUrl
    topic: str = Field(default="", max_length=256, pattern=r"^[^\s/]*$")
    target_id: str | None = None
    enabled: bool = True
    event_types: list[EventType] = Field(default_factory=default_event_types, min_length=1)
    severities: list[EventSeverity] = Field(
        default_factory=default_event_severities, min_length=1
    )
    token: str | None = None
    signing_secret: str | None = Field(default=None, min_length=16, max_length=4096)

    @model_validator(mode="after")
    def validate_channel_kind(self) -> ChannelCreate:
        if self.kind == "ntfy" and not self.topic:
            raise ValueError("topic is required for ntfy channels")
        if self.kind == "ntfy" and self.signing_secret is not None:
            raise ValueError("signing_secret is only accepted for webhook channels")
        return self


class ChannelUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    kind: Literal["ntfy", "webhook"] | None = None
    server_url: HttpUrl | None = None
    topic: str | None = Field(default=None, max_length=256, pattern=r"^[^\s/]*$")
    target_id: str | None = None
    enabled: bool | None = None
    event_types: list[EventType] | None = Field(default=None, min_length=1)
    severities: list[EventSeverity] | None = Field(
        default=None, min_length=1
    )
    token: str | None = None
    signing_secret: str | None = Field(default=None, min_length=16, max_length=4096)


class ChannelResponse(ORMModel):
    id: str
    target_id: str | None
    name: str
    kind: str
    server_url: str
    topic: str
    enabled: bool
    event_types: list[str]
    severities: list[str]
    token_configured: bool = False
    signing_secret_configured: bool = False
    created_at: datetime


class AutomationRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    target_id: str | None = None
    enabled: bool = False
    trigger_rule_key: Literal["account.unavailable"] = "account.unavailable"
    action: Literal[
        "recover_state",
        "clear_error",
        "clear_rate_limit",
        "clear_temp_unschedulable",
        "set_schedulable",
    ]
    mode: Literal["recommend", "execute"] = "recommend"
    reason_filters: list[
        Literal[
            "status:error",
            "manually_unschedulable",
            "rate_limited",
            "overloaded",
            "temporarily_unschedulable",
        ]
    ] = Field(min_length=1)
    reason_match_mode: Literal["any", "all"] = "any"
    cooldown_seconds: int = Field(default=900, ge=300, le=86400)
    confirm_side_effects: bool = False

    @model_validator(mode="after")
    def validate_execution_confirmation(self) -> AutomationRuleCreate:
        from app.services.automation import ACTION_REASON_ALLOWLIST

        allowed_reasons = ACTION_REASON_ALLOWLIST[self.action]
        invalid_reasons = set(self.reason_filters) - allowed_reasons
        if invalid_reasons:
            invalid = ", ".join(sorted(invalid_reasons))
            raise ValueError(f"reason_filters are incompatible with {self.action}: {invalid}")
        if self.enabled and self.action in {"recover_state", "set_schedulable"}:
            raise ValueError(f"{self.action} rules cannot be enabled for account fault automation")
        if self.enabled and self.mode == "execute":
            raise ValueError(
                "account fault execution rules cannot be enabled; manual approval is required"
            )
        return self


class AutomationRuleResponse(ORMModel):
    id: str
    target_id: str | None
    name: str
    enabled: bool
    trigger_rule_key: str
    action: str
    mode: str
    reason_filters: list[str]
    reason_match_mode: str
    cooldown_seconds: int
    created_at: datetime
    updated_at: datetime


class AutomationExecutionResponse(ORMModel):
    id: str
    rule_id: str | None
    incident_id: str | None
    transition_id: str
    target_id: str | None
    external_account_id: str
    action: str
    mode: str
    status: str
    attempts: int
    result: dict[str, Any]
    last_error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class CostRoutingPolicyUpdate(BaseModel):
    enabled: bool = False
    mode: Literal["recommend", "execute"] = "recommend"
    probe_interval_seconds: int = Field(default=30, ge=30, le=30)
    priority_scale: int = Field(default=1000, ge=1, le=1_000_000)
    unhealthy_priority: int = Field(default=100000, ge=2, le=2_000_000_000)
    minimum_priority: int = Field(default=1, ge=0, le=1_999_999_999)
    quality_bindings: dict[str, list[str]] = Field(default_factory=dict)
    confirm_side_effects: bool = False

    @model_validator(mode="after")
    def validate_cost_routing(self) -> CostRoutingPolicyUpdate:
        if self.unhealthy_priority <= self.minimum_priority:
            raise ValueError("unhealthy_priority must be greater than minimum_priority")
        if self.enabled and not self.confirm_side_effects:
            raise ValueError("confirm_side_effects is required when enabling cost routing")
        if len(self.quality_bindings) > 10_000:
            raise ValueError("quality_bindings exceeds the account limit")
        normalized: dict[str, list[str]] = {}
        for raw_account_id, raw_monitor_ids in self.quality_bindings.items():
            account_id = raw_account_id.strip()
            if not account_id or len(account_id) > 160:
                raise ValueError("quality_bindings contains an invalid account id")
            if len(raw_monitor_ids) > 100:
                raise ValueError("quality_bindings exceeds the per-account monitor limit")
            monitor_ids = list(
                dict.fromkeys(item.strip() for item in raw_monitor_ids if item.strip())
            )
            if any(len(item) > 160 for item in monitor_ids):
                raise ValueError("quality_bindings contains an invalid monitor id")
            if monitor_ids:
                normalized[account_id] = monitor_ids
        self.quality_bindings = normalized
        return self


class CostRoutingPolicyResponse(ORMModel):
    id: str | None = None
    target_id: str
    enabled: bool = False
    mode: str = "recommend"
    probe_interval_seconds: int = 30
    priority_scale: int = 1000
    unhealthy_priority: int = 100000
    minimum_priority: int = 1
    quality_bindings: dict[str, list[str]] = Field(default_factory=dict)
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    last_error: str | None = None
    last_account_count: int = 0
    last_change_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None


class CostRoutingRunRequest(BaseModel):
    confirm_side_effects: bool = False


class RoutingDecisionResponse(ORMModel):
    id: str
    policy_id: str | None
    target_id: str | None
    external_account_id: str
    account_name: str
    observed_multiplier: float | None
    previous_priority: int | None
    desired_priority: int
    reason: str
    mode: str
    status: str
    result: dict[str, Any]
    last_error: str | None
    created_at: datetime
    finished_at: datetime | None


class AccountActionRequest(BaseModel):
    confirm_side_effects: bool = False

    @model_validator(mode="after")
    def validate_confirmation(self) -> AccountActionRequest:
        if not self.confirm_side_effects:
            raise ValueError("confirm_side_effects is required")
        return self


class OutboxResponse(ORMModel):
    id: str
    incident_id: str | None
    transition_id: str
    channel_id: str
    channel_name: str | None = None
    channel_kind: str | None = None
    status: str
    attempts: int = Field(description="Number of failed delivery attempts")
    next_attempt_at: datetime
    last_error: str | None
    sent_at: datetime | None
    created_at: datetime


class SystemStatus(BaseModel):
    database: str
    ready: bool
    worker_last_seen_at: datetime | None
    worker_stale: bool
    pending_outbox: int
    failed_runs_24h: int


class DashboardResponse(BaseModel):
    targets_total: int
    targets_ready: int
    accounts_total: int
    accounts_available: int
    low_quota_accounts: int
    active_incidents: int
    failed_collections_24h: int
    channels_total: int = 0
    channels_unhealthy: int = 0


class UpstreamBillingSettings(BaseModel):
    enabled: bool
    interval_minutes: int = Field(ge=5, le=1440)


class UpstreamBillingProbeToggle(BaseModel):
    enabled: bool


class UpstreamBillingBatchRequest(BaseModel):
    account_ids: list[str] = Field(min_length=1, max_length=20)


class UpstreamBillingProbeResponse(BaseModel):
    account_id: str
    target_id: str
    external_account_id: str
    snapshot: dict[str, Any] | None = None


class ChannelMonitorCreate(BaseModel):
    target_id: str
    name: str = Field(min_length=1, max_length=100)
    provider: Literal["openai", "anthropic", "gemini", "grok"]
    api_mode: Literal["chat_completions", "responses"] = "chat_completions"
    endpoint: HttpUrl
    api_key: str = Field(min_length=1, max_length=2000)
    primary_model: str = Field(default="", max_length=200)
    extra_models: list[str] = Field(default_factory=list, max_length=50)
    group_name: str = Field(default="", max_length=100)
    enabled: bool = True
    interval_seconds: int = Field(default=60, ge=15, le=3600)
    jitter_seconds: int = Field(default=0, ge=0, le=3585)
    template_id: int | None = None
    extra_headers: dict[str, str] = Field(default_factory=dict)
    body_override_mode: Literal["off", "merge", "replace"] = "off"
    body_override: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_jitter(self) -> ChannelMonitorCreate:
        if self.jitter_seconds >= self.interval_seconds:
            raise ValueError("jitter_seconds must be lower than interval_seconds")
        return self


class ChannelMonitorUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    provider: Literal["openai", "anthropic", "gemini", "grok"] | None = None
    api_mode: Literal["chat_completions", "responses"] | None = None
    endpoint: HttpUrl | None = None
    api_key: str | None = Field(default=None, max_length=2000)
    primary_model: str | None = Field(default=None, max_length=200)
    extra_models: list[str] | None = Field(default=None, max_length=50)
    group_name: str | None = Field(default=None, max_length=100)
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=15, le=3600)
    jitter_seconds: int | None = Field(default=None, ge=0, le=3585)
    template_id: int | None = None
    clear_template: bool = False
    extra_headers: dict[str, str] | None = None
    body_override_mode: Literal["off", "merge", "replace"] | None = None
    body_override: dict[str, Any] | None = None


class ChannelMonitorResponse(ORMModel):
    id: str
    target_id: str
    external_monitor_id: str
    name: str
    provider: str
    api_mode: str
    endpoint: str
    api_key_masked: str
    api_key_decrypt_failed: bool
    primary_model: str
    extra_models: list[str]
    group_name: str
    enabled: bool
    interval_seconds: int
    jitter_seconds: int
    last_checked_at: datetime | None
    primary_status: str
    primary_latency_ms: int | None
    availability_7d: float
    extra_models_status: list[dict[str, Any]]
    template_id: str | None
    extra_headers: dict[str, str]
    body_override_mode: str
    body_override: dict[str, Any] | None
    source_created_at: datetime | None
    source_updated_at: datetime | None
    observed_at: datetime
    target_name: str | None = None


class ChannelCheckResponse(BaseModel):
    model: str
    status: str
    latency_ms: int | None
    ping_latency_ms: int | None
    message: str
    checked_at: datetime
