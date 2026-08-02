import { apiClient } from '../client'
import type { PaginatedResponse } from '@/types'

export type LoginCaptchaIPStatus = 'blocked' | 'monitoring' | 'cleared'

export interface LoginCaptchaIPRecord {
  id: number
  client_ip: string
  failure_count: number
  total_failures: number
  block_count: number
  window_started_at: string
  first_failed_at: string
  last_failed_at: string
  last_success_at?: string
  blocked_until?: string
  last_user_agent: string
  resolved_at?: string
  resolved_by_user_id?: number
  resolution_note: string
  status: LoginCaptchaIPStatus
}

export interface LoginCaptchaIPQuery {
  page?: number
  page_size?: number
  q?: string
  status?: '' | LoginCaptchaIPStatus
}

export async function listIPRecords(params: LoginCaptchaIPQuery): Promise<PaginatedResponse<LoginCaptchaIPRecord>> {
  const { data } = await apiClient.get<PaginatedResponse<LoginCaptchaIPRecord>>('/admin/login-security/ip-records', { params })
  return data
}

export async function unblockIP(id: number): Promise<LoginCaptchaIPRecord> {
  const { data } = await apiClient.post<LoginCaptchaIPRecord>(`/admin/login-security/ip-records/${id}/unblock`, {})
  return data
}

export default { listIPRecords, unblockIP }
