<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import IconField from 'primevue/iconfield'
import InputIcon from 'primevue/inputicon'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'

import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import { api, type RunDto } from '@/shared/api/client'

const { t, locale } = useI18n()
const router = useRouter()
const search = ref('')
const statusFilter = ref<string | null>(null)
const runsQuery = useQuery({
  queryKey: ['runs'],
  queryFn: () => api.runs(200),
  refetchInterval: 10_000,
})
const statusOptions = computed(() =>
  ['QUEUED', 'PREPARING', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELED', 'TIMED_OUT', 'INTERRUPTED', 'REJECTED']
    .map((value) => ({ value, label: t(`status.${value}`) })),
)
const runs = computed(() => {
  const needle = search.value.trim().toLocaleLowerCase()
  return (runsQuery.data.value ?? []).filter((run) => {
    if (statusFilter.value && run.status !== statusFilter.value) return false
    if (!needle) return true
    return [run.runId, run.kind, run.status, JSON.stringify(run.operationSpec)]
      .some((value) => value.toLocaleLowerCase().includes(needle))
  })
})

function date(value: string): string {
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value))
}

function duration(run: RunDto): string {
  if (!run.startedAt) return '—'
  const end = run.finishedAt ? new Date(run.finishedAt).getTime() : Date.now()
  const seconds = Math.max(0, Math.round((end - new Date(run.startedAt).getTime()) / 1000))
  return t('runs.seconds', { value: seconds })
}

function operation(run: RunDto): string {
  if (run.kind === 'COMMAND') return String(run.operationSpec.command ?? '')
  if (run.kind === 'PLAYBOOK') {
    const reference = run.operationSpec.playbook
    if (reference && typeof reference === 'object' && !Array.isArray(reference)) {
      const values = reference as Record<string, unknown>
      if (typeof values.path === 'string') return values.path
      if (typeof values.playbookId === 'string') {
        const revision = typeof values.revision === 'number' ? `@${values.revision}` : ''
        return `database:${values.playbookId.slice(0, 8)}${revision}`
      }
    }
    return String(run.operationSpec.playbookPath ?? '')
  }
  return 'ansible.builtin.ping'
}

function open(event: { data: RunDto }): void {
  void router.push({ name: 'run-detail', params: { id: event.data.runId } })
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('runs.title')" :description="t('runs.description')">
      <Button icon="pi pi-terminal" :label="t('dashboard.runCommand')" @click="router.push('/commands')" />
    </PageHeader>
    <section class="surface-card">
      <div class="table-toolbar">
        <IconField>
          <InputIcon class="pi pi-search" />
          <InputText v-model="search" :placeholder="t('runs.search')" />
        </IconField>
        <Select
          v-model="statusFilter"
          :options="statusOptions"
          option-label="label"
          option-value="value"
          show-clear
          :placeholder="t('runs.allStatuses')"
        />
        <Button icon="pi pi-refresh" severity="secondary" outlined :aria-label="t('common.refresh')" :loading="runsQuery.isFetching.value" @click="runsQuery.refetch()" />
      </div>
      <DataTable
        :value="runs"
        :loading="runsQuery.isPending.value"
        data-key="runId"
        paginator
        :rows="20"
        :rows-per-page-options="[20, 50, 100]"
        striped-rows
        selection-mode="single"
        state-storage="local"
        state-key="ops-composer-runs"
        :table-props="{ 'aria-label': t('runs.title') }"
        @row-click="open"
      >
        <Column field="runId" :header="t('runs.id')">
          <template #body="{ data }"><code>{{ data.runId.slice(0, 8) }}</code></template>
        </Column>
        <Column field="kind" :header="t('runs.kind')" sortable />
        <Column :header="t('runs.operation')">
          <template #body="{ data }"><span class="operation-cell">{{ operation(data) }}</span></template>
        </Column>
        <Column :header="t('runs.targets')">
          <template #body="{ data }">{{ data.resolvedTargets.length }}</template>
        </Column>
        <Column field="status" :header="t('common.status')" sortable>
          <template #body="{ data }"><StatusTag :status="data.status" /></template>
        </Column>
        <Column :header="t('runs.duration')">
          <template #body="{ data }">{{ duration(data) }}</template>
        </Column>
        <Column field="createdAt" :header="t('common.createdAt')" sortable>
          <template #body="{ data }">{{ date(data.createdAt) }}</template>
        </Column>
        <template #empty>{{ t('runs.empty') }}</template>
      </DataTable>
    </section>
  </div>
</template>
