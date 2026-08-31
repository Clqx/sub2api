import { useEffect, useState } from "react";
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Play, RefreshCw, Route, Save } from "lucide-react";
import { api } from "../api";
import { Empty, ErrorState, Status } from "../components/Status";
import type {
  Account,
  CostRoutingPolicy,
  RoutingDecision,
  UpstreamBillingProbeSnapshot,
} from "../types";

export function RatesPage() {
  const client = useQueryClient();
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets });
  const [targetId, setTargetId] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [interval, setInterval] = useState(30);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [routingEnabled, setRoutingEnabled] = useState(false);
  const [routingMode, setRoutingMode] = useState<"recommend" | "execute">(
    "recommend",
  );
  const [priorityScale, setPriorityScale] = useState(1000);
  const [unhealthyPriority, setUnhealthyPriority] = useState(100000);
  const [minimumPriority, setMinimumPriority] = useState(1);
  const [fallbackAccountIds, setFallbackAccountIds] = useState<string[]>([]);

  useEffect(() => {
    if (!targetId && targets.data?.items.length)
      setTargetId(targets.data.items[0].id);
  }, [targetId, targets.data]);

  const settings = useQuery({
    queryKey: ["upstream-billing-settings", targetId],
    queryFn: () => api.upstreamBillingSettings(targetId),
    enabled: Boolean(targetId),
  });
  const routingPolicy = useQuery({
    queryKey: ["cost-routing-policy", targetId],
    queryFn: () => api.costRoutingPolicy(targetId),
    enabled: Boolean(targetId),
    refetchInterval: routingEnabled ? 10000 : false,
  });
  const decisions = useQuery({
    queryKey: ["routing-decisions", targetId],
    queryFn: () => api.routingDecisions(targetId),
    enabled: Boolean(targetId),
    refetchInterval: routingEnabled ? 10000 : false,
  });
  useEffect(() => {
    if (settings.data) {
      setEnabled(settings.data.enabled);
      setInterval(settings.data.interval_minutes);
    }
  }, [settings.data]);
  useEffect(() => {
    if (routingPolicy.data) {
      setRoutingEnabled(routingPolicy.data.enabled);
      setRoutingMode(routingPolicy.data.mode);
      setPriorityScale(routingPolicy.data.priority_scale);
      setUnhealthyPriority(routingPolicy.data.unhealthy_priority);
      setMinimumPriority(routingPolicy.data.minimum_priority);
      setFallbackAccountIds(routingPolicy.data.fallback_account_ids ?? []);
    }
  }, [routingPolicy.data]);

  const accounts = useInfiniteQuery({
    queryKey: ["upstream-billing-accounts", targetId],
    initialPageParam: null as string | null,
    enabled: Boolean(targetId),
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({
        target_id: targetId,
        platform: "openai",
        account_type: "apikey",
        limit: "100",
      });
      if (pageParam) params.set("cursor", pageParam);
      return api.accounts(`?${params}`);
    },
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });

  const save = useMutation({
    mutationFn: () =>
      api.updateUpstreamBillingSettings(targetId, {
        enabled,
        interval_minutes: interval,
      }),
    onSuccess: (data) =>
      client.setQueryData(["upstream-billing-settings", targetId], data),
  });
  const saveRouting = useMutation({
    mutationFn: (confirmSideEffects: boolean) =>
      api.updateCostRoutingPolicy(targetId, {
        enabled: routingEnabled,
        mode: routingMode,
        probe_interval_seconds: 30,
        priority_scale: priorityScale,
        unhealthy_priority: unhealthyPriority,
        minimum_priority: minimumPriority,
        quality_bindings: routingPolicy.data?.quality_bindings ?? {},
        fallback_account_ids: fallbackAccountIds,
        confirm_side_effects: confirmSideEffects,
      }),
    onSuccess: (data) => {
      client.setQueryData(["cost-routing-policy", targetId], data);
      client.invalidateQueries({ queryKey: ["routing-decisions", targetId] });
    },
  });
  const queueRoutingRun = useMutation({
    mutationFn: () => api.queueCostRoutingRun(targetId),
    onSuccess: (data) =>
      client.setQueryData(["cost-routing-policy", targetId], data),
  });
  const toggle = useMutation({
    mutationFn: ({ accountId, value }: { accountId: string; value: boolean }) =>
      api.toggleUpstreamBillingProbe(accountId, value),
    onSuccess: () =>
      client.invalidateQueries({
        queryKey: ["upstream-billing-accounts", targetId],
      }),
  });
  const probe = useMutation({
    mutationFn: (accountId: string) => api.probeUpstreamBilling(accountId),
    onSuccess: () =>
      client.invalidateQueries({
        queryKey: ["upstream-billing-accounts", targetId],
      }),
  });
  const batchProbe = useMutation({
    mutationFn: (accountIds: string[]) =>
      api.probeUpstreamBillingBatch(accountIds),
    onSuccess: () => {
      setSelected(new Set());
      client.invalidateQueries({
        queryKey: ["upstream-billing-accounts", targetId],
      });
    },
  });

  const rows =
    accounts.data?.pages
      .flatMap((page) => page.items)
      .filter(
        (account) =>
          account.platform.toLowerCase() === "openai" &&
          account.account_type.toLowerCase() === "apikey",
      ) ?? [];
  const allSelected = rows.length > 0 && rows.every((row) => selected.has(row.id));

  const submitRouting = () => {
    const confirmed =
      !routingEnabled ||
      window.confirm(
        routingMode === "execute"
          ? "启用后将每分钟探测并自动修改上游账号优先级，确认继续？"
          : "启用后将每分钟调用上游倍率探测接口，确认继续？",
      );
    if (confirmed) saveRouting.mutate(routingEnabled);
  };

  const runRoutingNow = () => {
    if (window.confirm("立即执行一次成本路由探测，确认继续？")) {
      queueRoutingRun.mutate();
    }
  };

  return (
    <>
      <div className="page-title">
        <div>
          <h1>上游倍率</h1>
          <p>服务质量、成本倍率与调度优先级</p>
        </div>
        <label>
          目标
          <select value={targetId} onChange={(event) => setTargetId(event.target.value)}>
            {targets.data?.items.map((target) => (
              <option key={target.id} value={target.id}>
                {target.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      <section className="content-band routing-settings">
        <div className="section-title">
          <div>
            <h2>一分钟成本路由</h2>
            <p>{routingPolicy.data?.enabled ? "运行中" : "未启用"}</p>
          </div>
          <Route size={19} />
        </div>
        {routingPolicy.isError ? (
          <ErrorState error={routingPolicy.error} />
        ) : (
          <>
            <div className="routing-controls">
              <label className="switch-label">
                <input
                  type="checkbox"
                  checked={routingEnabled}
                  onChange={(event) => setRoutingEnabled(event.target.checked)}
                />
                启用
              </label>
              <div className="control-group">
                <span>模式</span>
                <div className="segmented-control" role="group" aria-label="成本路由模式">
                  <button
                    type="button"
                    aria-pressed={routingMode === "recommend"}
                    onClick={() => setRoutingMode("recommend")}
                  >
                    建议
                  </button>
                  <button
                    type="button"
                    aria-pressed={routingMode === "execute"}
                    onClick={() => setRoutingMode("execute")}
                  >
                    自动执行
                  </button>
                </div>
              </div>
              <label>
                优先级刻度
                <input
                  type="number"
                  min="1"
                  max="1000000"
                  value={priorityScale}
                  onChange={(event) => setPriorityScale(Number(event.target.value))}
                />
              </label>
              <label>
                故障优先级
                <input
                  type="number"
                  min="2"
                  max="2000000000"
                  value={unhealthyPriority}
                  onChange={(event) => setUnhealthyPriority(Number(event.target.value))}
                />
              </label>
              <label>
                最小优先级
                <input
                  type="number"
                  min="0"
                  max="1999999999"
                  value={minimumPriority}
                  onChange={(event) => setMinimumPriority(Number(event.target.value))}
                />
              </label>
              <button
                className="primary"
                aria-label="保存成本路由"
                disabled={!targetId || saveRouting.isPending}
                onClick={submitRouting}
              >
                <Save size={16} />
                保存
              </button>
              <button
                className="icon-button"
                title="立即运行成本路由"
                aria-label="立即运行成本路由"
                disabled={!routingPolicy.data?.enabled || queueRoutingRun.isPending}
                onClick={runRoutingNow}
              >
                <Play />
              </button>
            </div>
            <RoutingSummary policy={routingPolicy.data} />
            <FallbackAccounts
              accounts={rows}
              selected={fallbackAccountIds}
              baselines={routingPolicy.data?.fallback_priorities ?? {}}
              onChange={setFallbackAccountIds}
            />
            {(saveRouting.isError || queueRoutingRun.isError) && (
              <span className="form-error">
                {String(saveRouting.error ?? queueRoutingRun.error)}
              </span>
            )}
          </>
        )}
      </section>

      <section className="content-band rate-settings">
        <div className="section-title">
          <div>
            <h2>Sub2API 原生探测</h2>
            <p>
              {settings.data
                ? `${settings.data.interval_minutes} 分钟周期`
                : "目标配置"}
            </p>
          </div>
        </div>
        {settings.isError ? (
          <ErrorState error={settings.error} />
        ) : (
          <div className="inline-controls">
            <label className="switch-label">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(event) => setEnabled(event.target.checked)}
              />
              启用
            </label>
            <label>
              间隔（分钟）
              <input
                type="number"
                min="5"
                max="1440"
                value={interval}
                onChange={(event) => setInterval(Number(event.target.value))}
              />
            </label>
            <button
              className="primary"
              disabled={!targetId || save.isPending}
              onClick={() => save.mutate()}
            >
              <Save size={16} />
              保存
            </button>
            {save.isError && <span className="form-error">{String(save.error)}</span>}
          </div>
        )}
      </section>

      {accounts.isError ? (
        <ErrorState error={accounts.error} />
      ) : (
        <div className="table-wrap rate-table">
          <div className="batch-toolbar">
            <span>已选择 {selected.size} 个账号</span>
            <button
              className="primary"
              disabled={!selected.size || batchProbe.isPending}
              onClick={() => batchProbe.mutate([...selected])}
            >
              <RefreshCw size={16} />
              批量探测
            </button>
          </div>
          <table>
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    aria-label="选择全部账号"
                    checked={allSelected}
                    onChange={(event) =>
                      setSelected(
                        event.target.checked
                          ? new Set(rows.map((row) => row.id))
                          : new Set(),
                      )
                    }
                  />
                </th>
                <th>账号</th>
                <th>账号倍率</th>
                <th>有效倍率</th>
                <th title="数值越小越优先">当前优先级（小值优先）</th>
                <th>期望优先级</th>
                <th>路由状态</th>
                <th>探测结果</th>
                <th>下次原生探测</th>
                <th>自动探测</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((account) => (
                <RateRow
                  key={account.id}
                  account={account}
                  selected={selected.has(account.id)}
                  pending={toggle.isPending || probe.isPending || batchProbe.isPending}
                  onSelect={(value) =>
                    setSelected((current) => {
                      const next = new Set(current);
                      if (value) next.add(account.id);
                      else next.delete(account.id);
                      return next;
                    })
                  }
                  onToggle={(value) => toggle.mutate({ accountId: account.id, value })}
                  onProbe={() => probe.mutate(account.id)}
                />
              ))}
            </tbody>
          </table>
          {!rows.length && !accounts.isLoading && (
            <Empty title="没有账号" detail="目标完成采集后会显示倍率探测状态" />
          )}
          {accounts.hasNextPage && (
            <div className="load-more">
              <button
                onClick={() => accounts.fetchNextPage()}
                disabled={accounts.isFetchingNextPage}
              >
                加载更多
              </button>
            </div>
          )}
        </div>
      )}

      <RoutingHistory decisions={decisions.data ?? []} loading={decisions.isLoading} />
    </>
  );
}

function RoutingSummary({ policy }: { policy?: CostRoutingPolicy }) {
  return (
    <div className="routing-summary">
      <span>
        <small>探测周期</small>
        <strong>{policy?.probe_interval_seconds ?? 30} 秒</strong>
      </span>
      <span>
        <small>上次运行</small>
        <strong>{formatTime(policy?.last_run_at)}</strong>
      </span>
      <span>
        <small>下次运行</small>
        <strong>{formatTime(policy?.next_run_at)}</strong>
      </span>
      <span>
        <small>账号 / 调整</small>
        <strong>
          {policy?.last_account_count ?? 0} / {policy?.last_change_count ?? 0}
        </strong>
      </span>
      {policy?.last_error && (
        <span className="routing-error">
          <small>运行错误</small>
          <strong>{policy.last_error}</strong>
        </span>
      )}
    </div>
  );
}

function FallbackAccounts({
  accounts,
  selected,
  baselines,
  onChange,
}: {
  accounts: Account[];
  selected: string[];
  baselines: Record<string, number>;
  onChange: (value: string[]) => void;
}) {
  if (!accounts.length) return null;
  const selectedSet = new Set(selected);
  return (
    <div className="quality-bindings fallback-accounts">
      <h3>兜底账号</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>账号</th>
              <th>基线优先级</th>
              <th>不按倍率抑制</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((account) => {
              const accountId = account.external_account_id;
              return (
                <tr key={account.id}>
                  <td><strong>{account.name}</strong></td>
                  <td className="numeric-value">
                    {formatPriority(baselines[accountId] ?? account.priority)}
                  </td>
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`${account.name} 设为兜底账号`}
                      checked={selectedSet.has(accountId)}
                      onChange={(event) => onChange(
                        event.target.checked
                          ? [...selected, accountId]
                          : selected.filter((item) => item !== accountId),
                      )}
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RateRow({
  account,
  selected,
  pending,
  onSelect,
  onToggle,
  onProbe,
}: {
  account: Account;
  selected: boolean;
  pending: boolean;
  onSelect: (value: boolean) => void;
  onToggle: (value: boolean) => void;
  onProbe: () => void;
}) {
  const snapshot = account.upstream_billing_probe;
  const data = snapshot?.data;
  const effective =
    readNumber(data, "effective_rate_multiplier") ??
    readNumber(data, "resolved_rate_multiplier");
  return (
    <tr>
      <td>
        <input
          type="checkbox"
          aria-label={`选择 ${account.name}`}
          checked={selected}
          onChange={(event) => onSelect(event.target.checked)}
        />
      </td>
      <td>
        <strong>{account.name}</strong>
        <small>
          {account.target_name} · {account.platform}/{account.account_type}
        </small>
      </td>
      <td className="numeric-value">{formatRate(account.rate_multiplier)}</td>
      <td className="numeric-value">{formatRate(effective)}</td>
      <td className="numeric-value">{formatPriority(account.priority)}</td>
      <td className="numeric-value">
        {formatPriority(account.routing_desired_priority)}
      </td>
      <td>
        <Status value={routingStatus(account.routing_status)} />
        {account.routing_applied_at && <small>{formatTime(account.routing_applied_at)}</small>}
      </td>
      <td>
        <ProbeStatus snapshot={snapshot} />
        {snapshot?.last_error && <small className="danger-text">{snapshot.last_error}</small>}
      </td>
      <td>{formatTime(snapshot?.next_probe_at)}</td>
      <td>
        <label className="row-toggle">
          <input
            type="checkbox"
            checked={account.upstream_billing_probe_enabled}
            disabled={pending}
            onChange={(event) => onToggle(event.target.checked)}
          />
          <span>
            {account.upstream_billing_rate_sync_enabled ? "探测并同步" : "仅探测"}
          </span>
        </label>
      </td>
      <td className="actions sticky-actions">
        <button
          className="icon-button"
          title="立即探测上游倍率"
          aria-label={`探测 ${account.name} 上游倍率`}
          disabled={pending}
          onClick={onProbe}
        >
          <RefreshCw />
        </button>
      </td>
    </tr>
  );
}

function RoutingHistory({
  decisions,
  loading,
}: {
  decisions: RoutingDecision[];
  loading: boolean;
}) {
  return (
    <section className="routing-history">
      <div className="section-title">
        <div>
          <h2>最近路由决策</h2>
          <p>{decisions.length} 条记录</p>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>账号</th>
              <th>原因</th>
              <th>倍率</th>
              <th>优先级变化</th>
              <th>模式</th>
              <th>结果</th>
            </tr>
          </thead>
          <tbody>
            {decisions.map((decision) => (
              <tr key={decision.id}>
                <td>{formatTime(decision.created_at)}</td>
                <td>
                  <strong>{decision.account_name}</strong>
                  <small>{decision.external_account_id}</small>
                </td>
                <td>{reasonLabel(decision.reason)}</td>
                <td className="numeric-value">{formatRate(decision.observed_multiplier)}</td>
                <td className="numeric-value">
                  {formatPriority(decision.previous_priority)} → {decision.desired_priority}
                </td>
                <td>{decision.mode === "execute" ? "自动执行" : "建议"}</td>
                <td>
                  <Status value={decision.status} />
                  {decision.last_error && (
                    <small className="danger-text">{decision.last_error}</small>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!decisions.length && !loading && (
          <Empty title="没有路由决策" detail="优先级需要调整时会生成记录" />
        )}
      </div>
    </section>
  );
}

function ProbeStatus({
  snapshot,
}: {
  snapshot?: UpstreamBillingProbeSnapshot | null;
}) {
  if (!snapshot) return <Status value="missing" />;
  const fresh = snapshot.fresh_until
    ? new Date(snapshot.fresh_until).getTime() > Date.now()
    : false;
  return (
    <span className="probe-result">
      <Status
        value={
          snapshot.status === "ok" ? (fresh ? "fresh" : "stale") : snapshot.status
        }
      />
      <small>{formatTime(snapshot.last_attempt_at)}</small>
    </span>
  );
}

function routingStatus(value: Account["routing_status"]) {
  if (value === "in_sync" || value === "succeeded") return "healthy";
  if (value === "failed") return "failed";
  if (value === "cancelled") return "cancelled";
  if (value === "recommend" || value === "recommended") return "recommended";
  return "missing";
}

function reasonLabel(reason: RoutingDecision["reason"]) {
  return {
    cost_increase: "倍率上升",
    cost_decrease: "倍率下降",
    fallback_protected: "兜底保护",
    cost_discovered: "发现倍率",
    unavailable: "服务不可用",
    probe_failed: "倍率探测失败",
    quality_failed: "服务质量异常",
    recovery: "服务恢复",
    priority_reconcile: "优先级校准",
    in_sync: "已同步",
  }[reason];
}

function readNumber(data: Record<string, unknown> | undefined, key: string) {
  const value = data?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}
function formatRate(value: number | null | undefined) {
  return value == null
    ? "--"
    : `×${value.toFixed(4).replace(/0+$/, "").replace(/\.$/, "")}`;
}
function formatPriority(value: number | null | undefined) {
  return value == null ? "--" : value.toLocaleString("zh-CN");
}
function formatTime(value?: string | null) {
  return value ? new Date(value).toLocaleString("zh-CN") : "--";
}
