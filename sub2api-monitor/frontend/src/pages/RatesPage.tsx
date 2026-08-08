import { useEffect, useState } from "react";
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { RefreshCw, Save } from "lucide-react";
import { api } from "../api";
import { Empty, ErrorState, Status } from "../components/Status";
import type { Account, UpstreamBillingProbeSnapshot } from "../types";

export function RatesPage() {
  const client = useQueryClient();
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets });
  const [targetId, setTargetId] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [interval, setInterval] = useState(30);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  useEffect(() => {
    if (!targetId && targets.data?.items.length)
      setTargetId(targets.data.items[0].id);
  }, [targetId, targets.data]);
  const settings = useQuery({
    queryKey: ["upstream-billing-settings", targetId],
    queryFn: () => api.upstreamBillingSettings(targetId),
    enabled: Boolean(targetId),
  });
  useEffect(() => {
    if (settings.data) {
      setEnabled(settings.data.enabled);
      setInterval(settings.data.interval_minutes);
    }
  }, [settings.data]);
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
  return (
    <>
      <div className="page-title">
        <div>
          <h1>上游倍率</h1>
          <p>跨目标汇总账号成本倍率与探测新鲜度</p>
        </div>
        <label>
          目标
          <select
            value={targetId}
            onChange={(event) => setTargetId(event.target.value)}
          >
            {targets.data?.items.map((target) => (
              <option key={target.id} value={target.id}>
                {target.name}
              </option>
            ))}
          </select>
        </label>
      </div>
      <section className="content-band rate-settings">
        <div className="section-title">
          <div>
            <h2>自动探测</h2>
            <p>
              {settings.data
                ? `目标配置 · ${settings.data.interval_minutes} 分钟周期`
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
            {save.isError && (
              <span className="form-error">{String(save.error)}</span>
            )}
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
                <th>探测结果</th>
                <th>上游声明</th>
                <th>高峰倍率</th>
                <th>下次探测</th>
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
                  onToggle={(value) =>
                    toggle.mutate({ accountId: account.id, value })
                  }
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
    </>
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
  const declared =
    readNumber(data, "resolved_rate_multiplier") ??
    readNumber(data, "effective_rate_multiplier");
  const peak = readNumber(data, "peak_rate_multiplier");
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
      <td>
        <ProbeStatus snapshot={snapshot} />
        {snapshot?.last_error && (
          <small className="danger-text">{snapshot.last_error}</small>
        )}
      </td>
      <td className="numeric-value">{formatRate(declared)}</td>
      <td className="numeric-value">{formatRate(peak)}</td>
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
            {account.upstream_billing_rate_sync_enabled
              ? "探测并同步"
              : "仅探测"}
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
          snapshot.status === "ok"
            ? fresh
              ? "fresh"
              : "stale"
            : snapshot.status
        }
      />
      <small>{formatTime(snapshot.last_attempt_at)}</small>
    </span>
  );
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
function formatTime(value?: string) {
  return value ? new Date(value).toLocaleString("zh-CN") : "--";
}
