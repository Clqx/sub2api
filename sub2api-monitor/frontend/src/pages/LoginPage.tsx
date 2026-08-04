import { FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Database, LogIn } from 'lucide-react'
import { api } from '../api'

export function LoginPage({onSuccess}:{onSuccess:()=>void}){
  const login=useMutation({mutationFn:({username,password}:{username:string,password:string})=>api.login(username,password),onSuccess})
  function submit(e:FormEvent<HTMLFormElement>){e.preventDefault();const f=new FormData(e.currentTarget);login.mutate({username:String(f.get('username')),password:String(f.get('password'))})}
  return <main className="login-page"><section className="login-panel"><div className="login-brand"><Database/><div><strong>Sub2API Monitor</strong><span>Operations Hub</span></div></div><form onSubmit={submit}><h1>管理员登录</h1><p>管理多个 Sub2API 实例的账号可用性与额度告警</p><label>用户名<input name="username" autoComplete="username" defaultValue="admin" required/></label><label>密码<input name="password" type="password" autoComplete="current-password" required/></label>{login.isError&&<div className="form-error">{login.error.message}</div>}<button className="primary" disabled={login.isPending}><LogIn size={17}/>{login.isPending?'验证中':'登录'}</button></form></section></main>
}
