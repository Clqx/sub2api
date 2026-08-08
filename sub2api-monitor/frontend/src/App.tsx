import { Activity, Bell, Database, Gauge, LayoutDashboard, Menu, RadioTower, Server, Settings, TrendingDown, Users, X } from 'lucide-react'
import { MouseEvent, useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './api'
import { AccountsPage } from './pages/AccountsPage'
import { IncidentsPage } from './pages/IncidentsPage'
import { NotificationsPage } from './pages/NotificationsPage'
import { OverviewPage } from './pages/OverviewPage'
import { SystemPage } from './pages/SystemPage'
import { TargetsPage } from './pages/TargetsPage'
import { LoginPage } from './pages/LoginPage'
import { ChannelsPage } from './pages/ChannelsPage'
import { OperationsPage } from './pages/OperationsPage'
import { RatesPage } from './pages/RatesPage'

const navigation = [
  { to: '/overview', label: '总览', icon: LayoutDashboard },
  { to: '/targets', label: '目标', icon: Server },
  { to: '/accounts', label: '账号', icon: Users },
  { to: '/operations', label: '运行监控', icon: Activity },
  { to: '/rates', label: '上游倍率', icon: TrendingDown },
  { to: '/channels', label: '渠道监测', icon: RadioTower },
  { to: '/incidents', label: '告警', icon: Bell },
  { to: '/notifications', label: '通知', icon: Gauge },
  { to: '/system', label: '系统', icon: Settings },
]

export function App() {
  const client = useQueryClient()
  const auth = useQuery({ queryKey:['me'], queryFn:api.me, retry:false, enabled:Boolean(localStorage.getItem('monitor_token')) })
  const [open, setOpen] = useState(false)
  const [path, setPath] = useState(window.location.pathname)
  useEffect(() => { const update = () => setPath(window.location.pathname); window.addEventListener('popstate', update); return () => window.removeEventListener('popstate', update) }, [])
  const navigate = (event: MouseEvent<HTMLAnchorElement>, to: string) => { event.preventDefault(); window.history.pushState({}, '', to); setPath(to); setOpen(false) }
  const page = path === '/targets' ? <TargetsPage/> : path === '/accounts' ? <AccountsPage/> : path === '/operations' ? <OperationsPage/> : path === '/rates' ? <RatesPage/> : path === '/channels' ? <ChannelsPage/> : path === '/incidents' ? <IncidentsPage/> : path === '/notifications' ? <NotificationsPage/> : path === '/system' ? <SystemPage/> : <OverviewPage/>
  if (!localStorage.getItem('monitor_token') || auth.isError) return <LoginPage onSuccess={()=>window.location.reload()}/>
  if (auth.isLoading) return <div className="auth-loading">正在验证管理会话</div>
  return <div className="app-shell">
    <aside className={`sidebar ${open ? 'open' : ''}`}>
      <div className="brand"><Database size={20} /><span>Sub2API Monitor</span><button className="icon-button mobile-only" onClick={() => setOpen(false)} aria-label="关闭导航"><X /></button></div>
      <nav>{navigation.map(({ to, label, icon: Icon }) => <a key={to} href={to} className={path === to || (path === '/' && to === '/overview') ? 'active' : ''} onClick={(event) => navigate(event, to)}><Icon size={18}/><span>{label}</span></a>)}</nav>
      <div className="sidebar-foot"><Activity size={15}/><span>Operations Hub</span></div>
    </aside>
    {open && <button className="scrim" aria-label="关闭导航" onClick={() => setOpen(false)} />}
    <main>
      <header className="topbar"><button className="icon-button mobile-only" onClick={() => setOpen(true)} aria-label="打开导航"><Menu /></button><div><span className="eyebrow">MULTI-TARGET ACCOUNT OPERATIONS</span><strong>监控中心</strong></div><button className="user-button" onClick={async()=>{await api.logout();client.clear();window.location.reload()}} title="退出登录">{auth.data?.username}</button></header>
      <div className="page-wrap">{page}</div>
    </main>
  </div>
}
