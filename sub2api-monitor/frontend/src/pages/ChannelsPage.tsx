import { FormEvent, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { History, Pencil, Play, Plus, Trash2, X } from "lucide-react";
import { api } from "../api";
import { Empty, ErrorState, Status } from "../components/Status";
import type { ChannelCheck, ChannelMonitor, Target } from "../types";

export function ChannelsPage() {
  const client = useQueryClient();
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets });
  const [targetId, setTargetId] = useState("");
  const [editing, setEditing] = useState<ChannelMonitor | null | undefined>(
    undefined,
  );
  const [detail, setDetail] = useState<ChannelMonitor | null>(null);
  const query = useQuery({
    queryKey: ["channel-monitors", targetId],
    queryFn: () =>
      api.channelMonitors(targetId ? `?target_id=${targetId}` : ""),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteChannelMonitor(id),
    onSuccess: () =>
      client.invalidateQueries({ queryKey: ["channel-monitors"] }),
  });
  const run = useMutation({
    mutationFn: (item: ChannelMonitor) => api.runChannelMonitor(item.id),
    onSuccess: (_, item) => {
      client.invalidateQueries({ queryKey: ["channel-monitors"] });
      client.invalidateQueries({ queryKey: ["channel-history", item.id] });
      setDetail(item);
    },
  });
  return (
    <>
      <div className="page-title">
        <div>
          <h1>渠道监测</h1>
          <p>模型可用率、响应延迟与失败状态</p>
        </div>
        <div className="page-actions">
          <label>
            目标
            <select
              value={targetId}
              onChange={(event) => setTargetId(event.target.value)}
            >
              <option value="">全部目标</option>
              {targets.data?.items.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.name}
                </option>
              ))}
            </select>
          </label>
          <button
            className="primary"
            disabled={!targets.data?.items.length}
            onClick={() => setEditing(null)}
          >
            <Plus size={17} />
            新建渠道
          </button>
        </div>
      </div>
      {query.isError ? (
        <ErrorState error={query.error} />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>渠道</th>
                <th>目标</th>
                <th>主模型</th>
                <th>状态</th>
                <th>延迟</th>
                <th>7 天可用率</th>
                <th>周期</th>
                <th>最近检测</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {query.data?.map((item) => (
                <tr key={item.id}>
                  <td>
                    <strong>{item.name}</strong>
                    <small>
                      {item.provider} · {item.group_name || "未分组"}
                    </small>
                  </td>
                  <td>{item.target_name ?? item.target_id}</td>
                  <td>
                    <strong>{item.primary_model || "--"}</strong>
                    <small>
                      {item.extra_models.length
                        ? `另有 ${item.extra_models.length} 个模型`
                        : item.api_mode}
                    </small>
                  </td>
                  <td>
                    <Status
                      value={
                        !item.enabled
                          ? "disabled"
                          : item.primary_status || "missing"
                      }
                    />
                    {item.api_key_decrypt_failed && (
                      <small className="danger-text">密钥无法解密</small>
                    )}
                  </td>
                  <td className="numeric-value">
                    {item.primary_latency_ms == null
                      ? "--"
                      : `${item.primary_latency_ms} ms`}
                  </td>
                  <td className="numeric-value">
                    {item.last_checked_at
                      ? `${item.availability_7d.toFixed(2)}%`
                      : "--"}
                  </td>
                  <td>
                    {item.interval_seconds}s
                    {item.jitter_seconds ? ` ±${item.jitter_seconds}s` : ""}
                  </td>
                  <td>{formatTime(item.last_checked_at)}</td>
                  <td className="actions sticky-actions">
                    <button
                      className="icon-button"
                      title="立即检测"
                      aria-label={`检测 ${item.name}`}
                      disabled={run.isPending || !item.enabled}
                      onClick={() => run.mutate(item)}
                    >
                      <Play />
                    </button>
                    <button
                      className="icon-button"
                      title="查看历史"
                      aria-label={`查看 ${item.name} 历史`}
                      onClick={() => setDetail(item)}
                    >
                      <History />
                    </button>
                    <button
                      className="icon-button"
                      title="编辑"
                      aria-label={`编辑 ${item.name}`}
                      onClick={() => setEditing(item)}
                    >
                      <Pencil />
                    </button>
                    <button
                      className="icon-button danger-button"
                      title="删除"
                      aria-label={`删除 ${item.name}`}
                      disabled={remove.isPending}
                      onClick={() => {
                        if (window.confirm(`删除渠道监测“${item.name}”？`))
                          remove.mutate(item.id);
                      }}
                    >
                      <Trash2 />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!query.data?.length && !query.isLoading && (
            <Empty
              title="没有渠道监测"
              detail="为目标创建第一条模型可用性检测"
            />
          )}
        </div>
      )}
      {editing !== undefined && (
        <ChannelForm
          targets={targets.data?.items ?? []}
          item={editing}
          onClose={() => setEditing(undefined)}
          onSaved={() => {
            setEditing(undefined);
            client.invalidateQueries({ queryKey: ["channel-monitors"] });
          }}
        />
      )}
      {detail && (
        <ChannelHistory
          item={detail}
          latestRun={run.data}
          onClose={() => setDetail(null)}
        />
      )}
    </>
  );
}

function ChannelForm({
  targets,
  item,
  onClose,
  onSaved,
}: {
  targets: Target[];
  item: ChannelMonitor | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [targetId, setTargetId] = useState(
    item?.target_id ?? targets[0]?.id ?? "",
  );
  const [name, setName] = useState(item?.name ?? "");
  const [provider, setProvider] = useState(item?.provider ?? "openai");
  const [apiMode, setApiMode] = useState(item?.api_mode ?? "chat_completions");
  const [endpoint, setEndpoint] = useState(item?.endpoint ?? "");
  const [apiKey, setApiKey] = useState("");
  const [primaryModel, setPrimaryModel] = useState(item?.primary_model ?? "");
  const [extraModels, setExtraModels] = useState(
    item?.extra_models.join(", ") ?? "",
  );
  const [groupName, setGroupName] = useState(item?.group_name ?? "");
  const [enabled, setEnabled] = useState(item?.enabled ?? true);
  const [interval, setInterval] = useState(item?.interval_seconds ?? 60);
  const [jitter, setJitter] = useState(item?.jitter_seconds ?? 0);
  const [headers, setHeaders] = useState(
    JSON.stringify(item?.extra_headers ?? {}, null, 2),
  );
  const [overrideMode, setOverrideMode] = useState(
    item?.body_override_mode ?? "off",
  );
  const [body, setBody] = useState(
    JSON.stringify(item?.body_override ?? {}, null, 2),
  );
  const [parseError, setParseError] = useState("");
  const save = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      item
        ? api.updateChannelMonitor(item.id, payload)
        : api.createChannelMonitor(payload),
    onSuccess: onSaved,
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    try {
      setParseError("");
      const payload: Record<string, unknown> = {
        name,
        provider,
        api_mode: apiMode,
        endpoint,
        primary_model: primaryModel,
        extra_models: extraModels
          .split(",")
          .map((value) => value.trim())
          .filter(Boolean),
        group_name: groupName,
        enabled,
        interval_seconds: interval,
        jitter_seconds: jitter,
        extra_headers: JSON.parse(headers || "{}"),
        body_override_mode: overrideMode,
        body_override: JSON.parse(body || "{}"),
      };
      if (!item) payload.target_id = targetId;
      if (apiKey) payload.api_key = apiKey;
      save.mutate(payload);
    } catch {
      setParseError("高级设置必须是有效的 JSON 对象");
    }
  };
  return (
    <div className="modal-backdrop">
      <div className="modal channel-form" role="dialog" aria-modal="true">
        <div className="modal-head">
          <div>
            <h2>{item ? "编辑渠道" : "新建渠道"}</h2>
            <p>
              {item?.target_name ??
                targets.find((target) => target.id === targetId)?.name}
            </p>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="关闭">
            <X />
          </button>
        </div>
        <form onSubmit={submit}>
          {!item && (
            <label>
              目标
              <select
                value={targetId}
                onChange={(event) => setTargetId(event.target.value)}
                required
              >
                {targets.map((target) => (
                  <option key={target.id} value={target.id}>
                    {target.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          <div className="form-row">
            <label>
              名称
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                required
                maxLength={100}
              />
            </label>
            <label>
              提供商
              <select
                value={provider}
                onChange={(event) =>
                  setProvider(event.target.value as typeof provider)
                }
              >
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
                <option value="gemini">Gemini</option>
                <option value="grok">Grok</option>
              </select>
            </label>
          </div>
          <label>
            端点
            <input
              type="url"
              value={endpoint}
              onChange={(event) => setEndpoint(event.target.value)}
              required
              placeholder="https://api.example.com"
            />
          </label>
          <label>
            API Key
            <input
              type="password"
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
              required={!item}
              placeholder={item ? `保留当前密钥（${item.api_key_masked}）` : ""}
            />
          </label>
          <div className="form-row">
            <label>
              API 模式
              <select
                value={apiMode}
                onChange={(event) =>
                  setApiMode(event.target.value as typeof apiMode)
                }
              >
                <option value="chat_completions">Chat Completions</option>
                <option value="responses">Responses</option>
              </select>
            </label>
            <label>
              分组
              <input
                value={groupName}
                onChange={(event) => setGroupName(event.target.value)}
              />
            </label>
          </div>
          <label>
            主模型
            <input
              value={primaryModel}
              onChange={(event) => setPrimaryModel(event.target.value)}
              maxLength={200}
            />
          </label>
          <label>
            附加模型（逗号分隔）
            <input
              value={extraModels}
              onChange={(event) => setExtraModels(event.target.value)}
            />
          </label>
          <div className="form-row">
            <label>
              检测周期（秒）
              <input
                type="number"
                min="15"
                max="3600"
                value={interval}
                onChange={(event) => setInterval(Number(event.target.value))}
              />
            </label>
            <label>
              抖动（秒）
              <input
                type="number"
                min="0"
                max={Math.max(0, interval - 1)}
                value={jitter}
                onChange={(event) => setJitter(Number(event.target.value))}
              />
            </label>
          </div>
          <label className="check-label">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(event) => setEnabled(event.target.checked)}
            />
            启用渠道监测
          </label>
          <details>
            <summary>高级请求设置</summary>
            <label>
              附加请求头（JSON）
              <textarea
                value={headers}
                onChange={(event) => setHeaders(event.target.value)}
                rows={4}
              />
            </label>
            <label>
              请求体模式
              <select
                value={overrideMode}
                onChange={(event) =>
                  setOverrideMode(event.target.value as typeof overrideMode)
                }
              >
                <option value="off">关闭</option>
                <option value="merge">合并</option>
                <option value="replace">替换</option>
              </select>
            </label>
            <label>
              请求体覆盖（JSON）
              <textarea
                value={body}
                onChange={(event) => setBody(event.target.value)}
                rows={5}
              />
            </label>
          </details>
          {(parseError || save.isError) && (
            <div className="form-error">{parseError || String(save.error)}</div>
          )}
          <div className="modal-actions">
            <button type="button" onClick={onClose}>
              取消
            </button>
            <button className="primary" disabled={save.isPending}>
              {save.isPending ? "保存中" : "保存"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function ChannelHistory({
  item,
  latestRun,
  onClose,
}: {
  item: ChannelMonitor;
  latestRun?: ChannelCheck[];
  onClose: () => void;
}) {
  const [model, setModel] = useState(item.primary_model);
  const history = useQuery({
    queryKey: ["channel-history", item.id, model],
    queryFn: () => api.channelMonitorHistory(item.id, model || undefined),
  });
  useEffect(() => setModel(item.primary_model), [item]);
  const models = [item.primary_model, ...item.extra_models].filter(Boolean);
  return (
    <div className="modal-backdrop">
      <div className="modal account-detail" role="dialog" aria-modal="true">
        <div className="modal-head">
          <div>
            <h2>{item.name}</h2>
            <p>
              {item.target_name} · {item.provider}
            </p>
          </div>
          <button
            className="icon-button"
            onClick={onClose}
            aria-label="关闭历史"
          >
            <X />
          </button>
        </div>
        <div className="detail-content">
          <div className="history-toolbar">
            <label>
              模型
              <select
                value={model}
                onChange={(event) => setModel(event.target.value)}
              >
                {models.map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
            <span>
              <Status value={item.primary_status || "missing"} /> 7 天可用率{" "}
              {item.availability_7d.toFixed(2)}%
            </span>
          </div>
          {latestRun?.length ? (
            <section className="latest-results">
              <h3>本次检测</h3>
              {latestRun.map((result) => (
                <CheckLine
                  key={`${result.model}-${result.checked_at}`}
                  item={result}
                />
              ))}
            </section>
          ) : null}
          {history.isError ? (
            <ErrorState error={history.error} />
          ) : (
            <div className="history-list">
              {history.data?.map((result) => (
                <CheckLine
                  key={`${result.model}-${result.checked_at}`}
                  item={result}
                />
              ))}
              {!history.data?.length && !history.isLoading && (
                <Empty
                  title="没有历史记录"
                  detail="渠道完成检测后会产生历史记录"
                />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function CheckLine({ item }: { item: ChannelCheck }) {
  return (
    <div>
      <Status value={item.status} />
      <strong>{item.model}</strong>
      <span>{item.latency_ms == null ? "--" : `${item.latency_ms} ms`}</span>
      <small>{item.message || "--"}</small>
      <time>{formatTime(item.checked_at)}</time>
    </div>
  );
}
function formatTime(value?: string | null) {
  return value ? new Date(value).toLocaleString("zh-CN") : "--";
}
