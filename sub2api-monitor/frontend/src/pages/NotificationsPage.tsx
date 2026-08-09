import { FormEvent, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BellRing, Plus, Power, PowerOff, Send, Trash2, Webhook } from 'lucide-react'
import { api } from '../api'
import { Empty, ErrorState, Status } from '../components/Status'

const eventOptions = [
  ['incident.firing','故障触发'],
  ['incident.escalated','级别升级'],
  ['incident.resolved','故障恢复'],
] as const

const severityOptions = [
  ['info','信息'],
  ['warning','警告'],
  ['critical','严重'],
] as const

export function NotificationsPage() {
  const qc = useQueryClient()
  const [kind,setKind] = useState<'ntfy'|'webhook'>('ntfy')
  const [serverUrl,setServerUrl] = useState('https://ntfy.sh')
  const targets = useQuery({queryKey:['targets'],queryFn:api.targets})
  const channels = useQuery({queryKey:['channels'],queryFn:api.channels})
  const outbox = useQuery({queryKey:['outbox'],queryFn:api.outbox,refetchInterval:3_000})
  const create = useMutation({mutationFn:api.createChannel,onSuccess:()=>qc.invalidateQueries({queryKey:['channels']})})
  const test = useMutation({mutationFn:api.testChannel,onSuccess:()=>qc.invalidateQueries({queryKey:['outbox']})})
  const update = useMutation({mutationFn:({id,enabled}:{id:string;enabled:boolean})=>api.updateChannel(id,{enabled}),onSuccess:()=>qc.invalidateQueries({queryKey:['channels']})})
  const remove = useMutation({mutationFn:api.deleteChannel,onSuccess:()=>qc.invalidateQueries({queryKey:['channels']})})
  const operationError = create.error ?? test.error ?? update.error ?? remove.error

  function switchKind(next:'ntfy'|'webhook') {
    setKind(next)
    setServerUrl(next==='ntfy'?'https://ntfy.sh':'')
  }

  function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    create.mutate({
      name:form.get('name'),kind,server_url:form.get('server_url'),
      topic:kind==='ntfy'?form.get('topic'):'',
      target_id:form.get('target_id')||null,
      token:form.get('token')||null,
      signing_secret:kind==='webhook'?(form.get('signing_secret')||null):null,
      event_types:form.getAll('event_types'),
      severities:form.getAll('severities'),
      enabled:form.get('enabled')==='on',
    })
  }

  return <>
    <div className="page-title"><div><h1>事件订阅</h1><p>ntfy 与签名 Webhook 的统一投递队列</p></div></div>
    {operationError&&<ErrorState error={operationError}/>}
    <div className="split-layout subscription-layout">
      <section className="content-band"><div className="section-title"><div><h2>新增订阅</h2><p>事件转换级过滤</p></div></div>
        <form className="settings-form" onSubmit={submit}>
          <fieldset><legend>订阅类型</legend><div className="segmented"><button type="button" className={kind==='ntfy'?'active':''} onClick={()=>switchKind('ntfy')}><BellRing size={16}/>ntfy</button><button type="button" className={kind==='webhook'?'active':''} onClick={()=>switchKind('webhook')}><Webhook size={16}/>Webhook</button></div></fieldset>
          <label>名称<input name="name" required placeholder={kind==='ntfy'?'生产告警':'故障事件总线'}/></label>
          <label>目标范围<select name="target_id"><option value="">全部目标</option>{targets.data?.items.map(target=><option value={target.id} key={target.id}>{target.name}</option>)}</select></label>
          <label>{kind==='ntfy'?'ntfy 服务地址':'Webhook 地址'}<input name="server_url" type="url" value={serverUrl} onChange={event=>setServerUrl(event.target.value)} placeholder={kind==='webhook'?'https://events.example.com/sub2api':''} required/></label>
          {kind==='ntfy'&&<label>Topic<input name="topic" required placeholder="sub2api-alerts"/></label>}
          <label>Bearer Token（可选）<input name="token" type="password" autoComplete="new-password"/></label>
          {kind==='webhook'&&<label>HMAC 签名密钥（可选）<input name="signing_secret" type="password" minLength={16} autoComplete="new-password"/></label>}
          <fieldset><legend>事件</legend><div className="check-grid">{eventOptions.map(([value,label])=><label className="check-label" key={value}><input name="event_types" type="checkbox" value={value} defaultChecked/>{label}</label>)}</div></fieldset>
          <fieldset><legend>级别</legend><div className="check-grid compact">{severityOptions.map(([value,label])=><label className="check-label" key={value}><input name="severities" type="checkbox" value={value} defaultChecked={value!=='info'}/>{label}</label>)}</div></fieldset>
          <label className="check-label"><input name="enabled" type="checkbox" defaultChecked/>启用订阅</label>
          <button className="primary" disabled={create.isPending}><Plus size={17}/>{create.isPending?'保存中':'保存订阅'}</button>
        </form>
      </section>
      <section className="content-band"><div className="section-title"><div><h2>已配置订阅</h2><p>{channels.data?.length??0} 个投递端点</p></div></div>
        {channels.isError?<ErrorState error={channels.error}/>:<div className="channel-list subscription-list">{channels.data?.map(channel=><div key={channel.id}><span className={`subscription-icon ${channel.kind}`}>{channel.kind==='webhook'?<Webhook/>:<BellRing/>}</span><div><strong>{channel.name}</strong><small>{targetName(targets.data?.items,channel.target_id)} · {channel.server_url}{channel.topic?` / ${channel.topic}`:''}</small><span className="filter-summary">{channel.event_types.map(eventLabel).join(' / ')} · {channel.severities.map(severityLabel).join(' / ')}</span></div><div className="subscription-security">{channel.kind==='webhook'&&channel.signing_secret_configured&&<span className="mode">HMAC</span>}<Status value={channel.enabled?'enabled':'disabled'}/></div><span className="channel-actions"><button className="icon-button" aria-label={`测试 ${channel.name}`} title="发送测试" disabled={test.isPending||!channel.enabled} onClick={()=>test.mutate(channel.id)}><Send/></button><button className="icon-button" aria-label={`${channel.enabled?'停用':'启用'} ${channel.name}`} title={channel.enabled?'停用订阅':'启用订阅'} disabled={update.isPending} onClick={()=>update.mutate({id:channel.id,enabled:!channel.enabled})}>{channel.enabled?<PowerOff/>:<Power/>}</button><button className="icon-button" aria-label={`删除 ${channel.name}`} title="删除订阅" disabled={remove.isPending} onClick={()=>{if(window.confirm(`删除订阅“${channel.name}”？`))remove.mutate(channel.id)}}><Trash2/></button></span></div>)}{channels.data?.length===0&&<Empty title="没有事件订阅" detail="新增 ntfy 或 Webhook 订阅"/>}</div>}
      </section>
    </div>
    <section className="content-band delivery-band"><div className="section-title"><div><h2>投递记录</h2><p>持久化重试与最终状态</p></div></div>
      {outbox.isError?<ErrorState error={outbox.error}/>:<div className="delivery-list">{outbox.data?.map(item=><div key={item.id}><Status value={item.status}/><span className="delivery-kind">{item.channel_kind==='webhook'?<Webhook/>:<BellRing/>}{item.channel_name??item.channel_id}</span><span>{new Date(item.created_at).toLocaleString('zh-CN')}</span><span>尝试 {item.attempts}</span><small>{item.last_error??(item.sent_at?`送达 ${new Date(item.sent_at).toLocaleString('zh-CN')}`:'等待投递')}</small></div>)}{outbox.data?.length===0&&<Empty title="没有投递记录" detail="测试或事件触发后会显示在这里"/>}</div>}
    </section>
  </>
}

function targetName(targets:{id:string;name:string}[]|undefined,targetId:string|null|undefined){return targetId?(targets?.find(target=>target.id===targetId)?.name??targetId):'全部目标'}
function eventLabel(value:string){return eventOptions.find(([event])=>event===value)?.[1]??value}
function severityLabel(value:string){return severityOptions.find(([severity])=>severity===value)?.[1]??value}
