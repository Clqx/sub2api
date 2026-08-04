import { FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Power, PowerOff, Send, Trash2 } from 'lucide-react'
import { api } from '../api'
import { Empty, ErrorState, Status } from '../components/Status'

export function NotificationsPage() {
  const qc = useQueryClient()
  const channels = useQuery({ queryKey:['channels'], queryFn:api.channels })
  const outbox = useQuery({ queryKey:['outbox'], queryFn:api.outbox, refetchInterval:3_000 })
  const create = useMutation({ mutationFn:api.createChannel, onSuccess:() => qc.invalidateQueries({ queryKey:['channels'] }) })
  const test = useMutation({ mutationFn:api.testChannel, onSuccess:() => qc.invalidateQueries({ queryKey:['outbox'] }) })
  const update = useMutation({ mutationFn:({ id, enabled }:{ id:string; enabled:boolean }) => api.updateChannel(id,{ enabled }), onSuccess:() => qc.invalidateQueries({ queryKey:['channels'] }) })
  const remove = useMutation({ mutationFn:api.deleteChannel, onSuccess:() => qc.invalidateQueries({ queryKey:['channels'] }) })
  function submit(e:FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const f = new FormData(e.currentTarget)
    create.mutate({ name:f.get('name'), server_url:f.get('server_url'), topic:f.get('topic'), token:f.get('token') || null, enabled:f.get('enabled') === 'on' })
  }
  return <>
    <div className="page-title"><div><h1>ntfy 通知</h1><p>告警内容会在发送前脱敏，失败进入持久重试队列</p></div></div>
    <div className="split-layout"><section className="content-band"><div className="section-title"><div><h2>新增渠道</h2><p>保存与测试是两个独立动作，测试不会重复创建渠道</p></div></div><form className="settings-form" onSubmit={submit}><label>渠道名称<input name="name" required placeholder="生产告警"/></label><label>ntfy 服务地址<input name="server_url" type="url" defaultValue="https://ntfy.sh" required/></label><label>Topic<input name="topic" required placeholder="sub2api-alerts"/></label><label>Access Token<input name="token" type="password" autoComplete="new-password"/></label><label className="check-label"><input name="enabled" type="checkbox" defaultChecked/>启用该通知渠道</label>{create.isError && <div className="form-error" role="alert">{create.error.message}</div>}<button className="primary" disabled={create.isPending}><Plus size={17}/>{create.isPending ? '保存中' : '保存渠道'}</button></form></section>
    <section className="content-band"><div className="section-title"><div><h2>已配置渠道</h2><p>测试请求先进入 outbox，实际送达状态显示在下方</p></div></div>{channels.isError ? <ErrorState error={channels.error}/> : <div className="channel-list">{channels.data?.map(channel => <div key={channel.id}><div><strong>{channel.name}</strong><small>{channel.server_url} / {channel.topic}</small></div><Status value={channel.enabled ? 'enabled' : 'disabled'}/><span className="channel-actions"><button className="icon-button" aria-label={`测试 ${channel.name}`} title="发送测试" disabled={test.isPending || !channel.enabled} onClick={() => test.mutate(channel.id)}><Send/></button><button className="icon-button" aria-label={`${channel.enabled ? '停用' : '启用'} ${channel.name}`} title={channel.enabled ? '停用渠道' : '启用渠道'} disabled={update.isPending} onClick={() => update.mutate({ id:channel.id, enabled:!channel.enabled })}>{channel.enabled ? <PowerOff/> : <Power/>}</button><button className="icon-button" aria-label={`删除 ${channel.name}`} title="删除渠道" disabled={remove.isPending} onClick={() => { if (window.confirm(`删除通知渠道 ${channel.name}？`)) remove.mutate(channel.id) }}><Trash2/></button></span></div>)}{channels.data?.length === 0 && <Empty title="还没有通知渠道" detail="先保存一个 ntfy 渠道"/>}</div>}{(test.isError || update.isError || remove.isError) && <div className="form-error" role="alert">{(test.error ?? update.error ?? remove.error)?.message}</div>}{test.isSuccess && <div className="success-message" aria-live="polite">测试通知已入队，等待 worker 投递</div>}</section></div>
    <section className="content-band delivery-band"><div className="section-title"><div><h2>投递记录</h2><p>sent 表示 ntfy 已接受，dead 表示重试耗尽或配置不可用</p></div></div>{outbox.isError ? <ErrorState error={outbox.error}/> : <div className="delivery-list">{outbox.data?.map(item => <div key={item.id}><Status value={item.status}/><span>{new Date(item.created_at).toLocaleString('zh-CN')}</span><span>尝试 {item.attempts}</span><small>{item.last_error ?? (item.sent_at ? `送达 ${new Date(item.sent_at).toLocaleString('zh-CN')}` : '等待投递')}</small></div>)}{outbox.data?.length === 0 && <Empty title="没有投递记录" detail="测试或告警触发后会显示在这里"/>}</div>}</section>
  </>
}
