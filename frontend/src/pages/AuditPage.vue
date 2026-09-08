<script setup lang="ts">
import { useMutation, useQuery } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import DatePicker from 'primevue/datepicker'
import Dialog from 'primevue/dialog'
import Fluid from 'primevue/fluid'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Tag from 'primevue/tag'
import { useToast } from 'primevue/usetoast'
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import PageHeader from '@/components/PageHeader.vue'
import { useAuthorization } from '@/features/auth/authorization'
import { api, type AuditEventDto } from '@/shared/api/client'

const { t, locale } = useI18n()
const toast = useToast()
const { can } = useAuthorization()
const now = new Date()
const filters = reactive({
  since: new Date(now.getTime() - 24 * 60 * 60 * 1000),
  until: now,
  action: '',
  outcome: '',
  source: '',
  runId: '',
  actorUserId: '',
  resourceType: '',
  resourceId: '',
  errorCode: '',
})
const applied = ref<Record<string, string | number | null | undefined>>({})
const beforeId = ref<number | null>(null)
const cursorHistory = ref<Array<number | null>>([])
const selected = ref<AuditEventDto | null>(null)
const detailVisible = ref(false)
const outcomes = ['', 'SUCCEEDED', 'FAILED', 'DENIED', 'NOOP', 'STARTED']
const sources = ['', 'API', 'WORKER', 'CLI', 'SYSTEM']

function buildFilters(cursor: number | null = beforeId.value) {
  return {
    since: filters.since?.toISOString(),
    until: filters.until?.toISOString(),
    action: filters.action.trim() || null,
    outcome: filters.outcome || null,
    source: filters.source || null,
    runId: filters.runId.trim() || null,
    actorUserId: filters.actorUserId.trim() || null,
    resourceType: filters.resourceType.trim() || null,
    resourceId: filters.resourceId.trim() || null,
    errorCode: filters.errorCode.trim() || null,
    beforeId: cursor,
    limit: 200,
  }
}

applied.value = buildFilters(null)
const queryKey = computed(() => ['audit-events', applied.value])
const eventsQuery = useQuery({
  queryKey,
  queryFn: () => api.auditEvents(applied.value),
  enabled: () => can('audit:read'),
})

function applyFilters(): void {
  beforeId.value = null
  cursorHistory.value = []
  applied.value = buildFilters(null)
}

function nextPage(): void {
  const next = eventsQuery.data.value?.nextCursor
  if (!next) return
  cursorHistory.value.push(beforeId.value)
  beforeId.value = next
  applied.value = buildFilters(next)
}

function previousPage(): void {
  if (!cursorHistory.value.length) return
  beforeId.value = cursorHistory.value.pop() ?? null
  applied.value = buildFilters(beforeId.value)
}

function showDetail(event: AuditEventDto): void {
  selected.value = event
  detailVisible.value = true
}

function formatDate(value: string): string {
  const parsed = new Date(value)
  if (!Number.isFinite(parsed.getTime())) return '—'
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(parsed)
}

function download(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

const exportMutation = useMutation({
  mutationFn: () => api.exportAuditEvents({ ...buildFilters(null), beforeId: null, limit: null }),
  onSuccess: (blob) => download(blob, `ops-composer-audit-${new Date().toISOString().slice(0, 10)}.jsonl`),
  onError: (error) => toast.add({ severity: 'error', summary: t('common.failed'), detail: error.message, life: 6000 }),
})
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('audit.title')" :description="t('audit.description')">
      <Button icon="pi pi-download" :label="t('audit.export')" :loading="exportMutation.isPending.value" @click="exportMutation.mutate()" />
    </PageHeader>
    <section class="surface-card">
      <Fluid>
        <form class="audit-filters" @submit.prevent="applyFilters">
          <div class="field"><label for="audit-since">{{ t('audit.since') }}</label><DatePicker id="audit-since" v-model="filters.since" show-time hour-format="24" show-icon /></div>
          <div class="field"><label for="audit-until">{{ t('audit.until') }}</label><DatePicker id="audit-until" v-model="filters.until" show-time hour-format="24" show-icon /></div>
          <div class="field"><label for="audit-action">{{ t('audit.action') }}</label><InputText id="audit-action" v-model="filters.action" placeholder="RUN_FAILED" /></div>
          <div class="field"><label for="audit-outcome">{{ t('audit.outcome') }}</label><Select id="audit-outcome" v-model="filters.outcome" :options="outcomes" :option-label="(value) => value ? t(`audit.outcomes.${value}`) : t('audit.any')" /></div>
          <div class="field"><label for="audit-source">{{ t('audit.source') }}</label><Select id="audit-source" v-model="filters.source" :options="sources" :option-label="(value) => value || t('audit.any')" /></div>
          <div class="field"><label for="audit-run">Run ID</label><InputText id="audit-run" v-model="filters.runId" /></div>
          <div class="field"><label for="audit-actor">{{ t('audit.actor') }}</label><InputText id="audit-actor" v-model="filters.actorUserId" /></div>
          <div class="field"><label for="audit-resource-type">{{ t('audit.resourceType') }}</label><InputText id="audit-resource-type" v-model="filters.resourceType" /></div>
          <div class="field"><label for="audit-resource-id">{{ t('audit.resourceId') }}</label><InputText id="audit-resource-id" v-model="filters.resourceId" /></div>
          <div class="field"><label for="audit-error-code">{{ t('audit.errorCode') }}</label><InputText id="audit-error-code" v-model="filters.errorCode" /></div>
          <Button type="submit" icon="pi pi-filter" :label="t('audit.apply')" />
        </form>
      </Fluid>
    </section>
    <section class="surface-card">
      <DataTable :value="eventsQuery.data.value?.items ?? []" :loading="eventsQuery.isPending.value" data-key="auditEventId" striped-rows :table-props="{ 'aria-label': t('audit.title') }">
        <Column field="occurredAt" :header="t('audit.time')"><template #body="{ data }">{{ formatDate(data.occurredAt) }}</template></Column>
        <Column field="eventAction" :header="t('audit.action')"><template #body="{ data }"><code>{{ data.eventAction }}</code></template></Column>
        <Column field="eventOutcome" :header="t('audit.outcome')"><template #body="{ data }"><Tag :severity="data.eventOutcome === 'SUCCEEDED' ? 'success' : data.eventOutcome === 'FAILED' || data.eventOutcome === 'DENIED' ? 'danger' : 'secondary'" :value="t(`audit.outcomes.${data.eventOutcome}`)" /></template></Column>
        <Column field="source" :header="t('audit.source')" />
        <Column field="resourceType" :header="t('audit.resource')"><template #body="{ data }"><div class="table-primary"><span>{{ data.resourceType ?? '—' }}</span><small>{{ data.resourceId ?? '' }}</small></div></template></Column>
        <Column field="errorCode" :header="t('audit.errorCode')"><template #body="{ data }"><code>{{ data.errorCode ?? '—' }}</code></template></Column>
        <Column :header="t('common.actions')"><template #body="{ data }"><Button icon="pi pi-eye" text rounded :aria-label="t('audit.details')" @click="showDetail(data)" /></template></Column>
        <template #empty>{{ t('audit.empty') }}</template>
      </DataTable>
      <div class="pagination-actions">
        <Button icon="pi pi-chevron-left" severity="secondary" text :label="t('audit.newer')" :disabled="!cursorHistory.length" @click="previousPage" />
        <Button icon="pi pi-chevron-right" icon-pos="right" severity="secondary" text :label="t('audit.older')" :disabled="!eventsQuery.data.value?.nextCursor" @click="nextPage" />
      </div>
    </section>

    <Dialog v-model:visible="detailVisible" modal :header="t('audit.details')" :style="{ width: 'min(820px, 96vw)' }">
      <dl v-if="selected" class="definition-list audit-detail">
        <div><dt>ID</dt><dd>{{ selected.auditEventId }}</dd></div>
        <div><dt>{{ t('audit.action') }}</dt><dd><code>{{ selected.eventAction }}</code></dd></div>
        <div><dt>{{ t('audit.request') }}</dt><dd><code>{{ selected.requestId ?? '—' }}</code></dd></div>
        <div><dt>{{ t('audit.actor') }}</dt><dd><code>{{ selected.actorUserId ?? '—' }}</code></dd></div>
        <div><dt>Run ID</dt><dd><code>{{ selected.runId ?? '—' }}</code></dd></div>
        <div><dt>{{ t('audit.metadata') }}</dt><dd><pre>{{ JSON.stringify(selected.metadata, null, 2) }}</pre></dd></div>
      </dl>
    </Dialog>
  </div>
</template>
