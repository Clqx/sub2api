<template>
  <AppLayout>
    <TablePageLayout>
      <template #filters>
        <div class="card p-4 sm:p-6">
          <div class="flex flex-wrap items-end justify-between gap-4">
            <div class="flex flex-1 flex-wrap items-end gap-4">
              <div class="w-full sm:min-w-[280px] sm:w-auto">
                <label class="input-label">{{ t('admin.loginSecurity.filters.keyword') }}</label>
                <div class="relative">
                  <Icon name="search" size="md" class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                  <input
                    v-model.trim="filters.q"
                    type="text"
                    class="input pl-10"
                    :placeholder="t('admin.loginSecurity.filters.keywordPlaceholder')"
                    @keyup.enter="search"
                  />
                </div>
              </div>
              <div class="w-full sm:min-w-[180px] sm:w-auto">
                <label class="input-label">{{ t('admin.loginSecurity.filters.status') }}</label>
                <Select v-model="filters.status" :options="statusOptions" @change="search" />
              </div>
            </div>
            <div class="flex w-full justify-end gap-3 sm:w-auto">
              <button type="button" class="btn btn-primary" :disabled="loading" @click="search">
                <Icon name="search" size="sm" class="mr-1.5" />
                {{ t('common.search') }}
              </button>
              <button type="button" class="btn btn-secondary" :disabled="loading" @click="resetFilters">
                <Icon name="refresh" size="sm" class="mr-1.5" />
                {{ t('common.reset') }}
              </button>
            </div>
          </div>
        </div>
      </template>

      <template #table>
        <DataTable :columns="columns" :data="records" :loading="loading" row-key="id">
          <template #cell-client_ip="{ value }">
            <span class="whitespace-nowrap font-mono font-medium text-gray-900 dark:text-white">{{ value }}</span>
          </template>

          <template #cell-status="{ row }">
            <span :class="statusClass(row.status)">
              <span class="h-1.5 w-1.5 rounded-full" :class="statusDotClass(row.status)"></span>
              {{ statusLabel(row.status) }}
            </span>
          </template>

          <template #cell-failures="{ row }">
            <span class="whitespace-nowrap tabular-nums text-gray-700 dark:text-gray-200">
              <strong>{{ row.failure_count }}</strong>
              <span class="mx-1 text-gray-300 dark:text-dark-500">/</span>
              {{ row.total_failures }}
            </span>
          </template>

          <template #cell-block_count="{ value }">
            <span class="tabular-nums">{{ value }}</span>
          </template>

          <template #cell-last_failed_at="{ value }">
            <span class="whitespace-nowrap text-gray-600 dark:text-gray-300">{{ formatDateTime(value) }}</span>
          </template>

          <template #cell-blocked_until="{ row }">
            <span v-if="row.status === 'blocked' && row.blocked_until" class="whitespace-nowrap font-medium text-red-600 dark:text-red-400">
              {{ formatDateTime(row.blocked_until) }}
            </span>
            <span v-else class="text-gray-400">-</span>
          </template>

          <template #cell-last_user_agent="{ value }">
            <span class="block max-w-[320px] truncate text-xs text-gray-500 dark:text-gray-400" :title="value">
              {{ value || '-' }}
            </span>
          </template>

          <template #cell-actions="{ row }">
            <button
              v-if="row.status === 'blocked'"
              type="button"
              class="inline-flex items-center gap-1.5 whitespace-nowrap font-medium text-primary-600 hover:text-primary-700 disabled:opacity-50 dark:text-primary-400"
              :disabled="unblockingId === row.id"
              @click="selectedRecord = row"
            >
              <Icon name="lock" size="sm" />
              {{ t('admin.loginSecurity.unblock') }}
            </button>
            <span v-else class="text-gray-400">-</span>
          </template>

          <template #empty>
            <div class="flex flex-col items-center py-10">
              <Icon name="shield" size="xl" class="mb-3 h-12 w-12 text-gray-300 dark:text-dark-600" />
              <p class="text-sm font-medium text-gray-500 dark:text-gray-400">{{ t('admin.loginSecurity.empty') }}</p>
            </div>
          </template>
        </DataTable>
      </template>

      <template #pagination>
        <Pagination
          v-if="total > 0"
          :total="total"
          :page="page"
          :page-size="pageSize"
          @update:page="onPageChange"
          @update:pageSize="onPageSizeChange"
        />
      </template>
    </TablePageLayout>

    <ConfirmDialog
      :show="selectedRecord !== null"
      :title="t('admin.loginSecurity.unblockConfirm.title')"
      :message="t('admin.loginSecurity.unblockConfirm.message', { ip: selectedRecord?.client_ip || '' })"
      :confirm-text="t('admin.loginSecurity.unblock')"
      :cancel-text="t('common.cancel')"
      @confirm="confirmUnblock"
      @cancel="selectedRecord = null"
    />
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { adminAPI, type LoginCaptchaIPRecord, type LoginCaptchaIPStatus } from '@/api/admin'
import AppLayout from '@/components/layout/AppLayout.vue'
import TablePageLayout from '@/components/layout/TablePageLayout.vue'
import DataTable from '@/components/common/DataTable.vue'
import type { Column } from '@/components/common/types'
import Pagination from '@/components/common/Pagination.vue'
import Select from '@/components/common/Select.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import Icon from '@/components/icons/Icon.vue'
import { formatDateTime } from '@/utils/format'
import { useAppStore } from '@/stores'

const { t } = useI18n()
const appStore = useAppStore()

const records = ref<LoginCaptchaIPRecord[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const loading = ref(false)
const unblockingId = ref<number | null>(null)
const selectedRecord = ref<LoginCaptchaIPRecord | null>(null)
const filters = reactive<{ q: string; status: '' | LoginCaptchaIPStatus }>({ q: '', status: '' })

const columns = computed<Column[]>(() => [
  { key: 'client_ip', label: t('admin.loginSecurity.columns.ip') },
  { key: 'status', label: t('admin.loginSecurity.columns.status') },
  { key: 'failures', label: t('admin.loginSecurity.columns.failures') },
  { key: 'block_count', label: t('admin.loginSecurity.columns.blocks') },
  { key: 'last_failed_at', label: t('admin.loginSecurity.columns.lastFailed') },
  { key: 'blocked_until', label: t('admin.loginSecurity.columns.blockedUntil') },
  { key: 'last_user_agent', label: t('admin.loginSecurity.columns.userAgent') },
  { key: 'actions', label: t('common.actions') }
])

const statusOptions = computed(() => [
  { value: '', label: t('admin.loginSecurity.filters.all') },
  { value: 'blocked', label: t('admin.loginSecurity.status.blocked') },
  { value: 'monitoring', label: t('admin.loginSecurity.status.monitoring') },
  { value: 'cleared', label: t('admin.loginSecurity.status.cleared') }
])

function statusLabel(status: LoginCaptchaIPStatus): string {
  return t(`admin.loginSecurity.status.${status}`)
}

function statusClass(status: LoginCaptchaIPStatus): string {
  const base = 'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium'
  if (status === 'blocked') return `${base} bg-red-50 text-red-700 dark:bg-red-950/40 dark:text-red-300`
  if (status === 'monitoring') return `${base} bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-300`
  return `${base} bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300`
}

function statusDotClass(status: LoginCaptchaIPStatus): string {
  if (status === 'blocked') return 'bg-red-500'
  if (status === 'monitoring') return 'bg-amber-500'
  return 'bg-emerald-500'
}

async function fetchRecords() {
  loading.value = true
  try {
    const result = await adminAPI.loginSecurity.listIPRecords({
      page: page.value,
      page_size: pageSize.value,
      q: filters.q || undefined,
      status: filters.status || undefined
    })
    records.value = result.items
    total.value = result.total
  } catch (error: any) {
    appStore.showError(error?.message || t('admin.loginSecurity.loadFailed'))
  } finally {
    loading.value = false
  }
}

function search() {
  page.value = 1
  fetchRecords()
}

function resetFilters() {
  filters.q = ''
  filters.status = ''
  search()
}

function onPageChange(value: number) {
  page.value = value
  fetchRecords()
}

function onPageSizeChange(value: number) {
  pageSize.value = value
  page.value = 1
  fetchRecords()
}

async function confirmUnblock() {
  const record = selectedRecord.value
  if (!record || unblockingId.value !== null) return
  unblockingId.value = record.id
  try {
    await adminAPI.loginSecurity.unblockIP(record.id)
    appStore.showSuccess(t('admin.loginSecurity.unblockConfirm.success', { ip: record.client_ip }))
    selectedRecord.value = null
    await fetchRecords()
  } catch (error: any) {
    appStore.showError(error?.message || t('admin.loginSecurity.unblockConfirm.failed'))
  } finally {
    unblockingId.value = null
  }
}

onMounted(fetchRecords)
</script>
