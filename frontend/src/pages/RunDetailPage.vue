<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Message from 'primevue/message'
import ProgressBar from 'primevue/progressbar'
import Skeleton from 'primevue/skeleton'
import Tab from 'primevue/tab'
import TabList from 'primevue/tablist'
import TabPanel from 'primevue/tabpanel'
import TabPanels from 'primevue/tabpanels'
import Tabs from 'primevue/tabs'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'

import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import {
  api,
  runEventSource,
  type RunEventDto,
} from '@/shared/api/client'

const props = defineProps<{ id: string }>()
const { t, locale } = useI18n()
const router = useRouter()
const queryClient = useQueryClient()
const confirm = useConfirm()
const toast = useToast()
const activeTab = ref('summary')
const liveEvents = ref<RunEventDto[]>([])
let source: EventSource | null = null
const terminal = new Set(['SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELED', 'TIMED_OUT', 'INTERRUPTED', 'REJECTED'])

const detailQuery = useQuery({
  queryKey: ['run', props.id],
  queryFn: () => api.run(props.id),
  refetchInterval: (query) => {
    const status = query.state.data?.run.status
    return status && terminal.has(status) ? false : 5000
  },
})
const eventsQuery = useQuery({
  queryKey: ['run-events', props.id],
  queryFn: () => api.runEvents(props.id),
})
const events = computed(() => {
  const merged = new Map<number, RunEventDto>()
  for (const event of eventsQuery.data.value ?? []) merged.set(event.sequence, event)
  for (const event of liveEvents.value) merged.set(event.sequence, event)
  return [...merged.values()].sort((a, b) => a.sequence - b.sequence)
})
const run = computed(() => detailQuery.data.value?.run)
const targets = computed(() => detailQuery.data.value?.targets ?? [])
const completion = computed(() => {
  if (!targets.value.length) return 0
  const completed = targets.value.filter((target) => !['PENDING', 'RUNNING'].includes(target.status)).length
  return Math.round((completed / targets.value.length) * 100)
})
const canCancel = computed(() => run.value && !terminal.has(run.value.status))

const cancelMutation = useMutation({
  mutationFn: () => api.cancelRun(props.id),
  onSuccess: async () => {
    await queryClient.invalidateQueries({ queryKey: ['run', props.id] })
    toast.add({ severity: 'success', summary: t('runDetail.cancelRequested'), life: 2500 })
  },
})
const retryMutation = useMutation({
  mutationFn: () => api.retryRun(props.id),
  onSuccess: (value) => void router.push({ name: 'run-detail', params: { id: value.runId } }),
})

function date(value: string | null | undefined): string {
  if (!value) return '—'
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value))
}

function appendMessage(message: MessageEvent<string>): void {
  try {
    const event = JSON.parse(message.data) as RunEventDto
    if (!events.value.some((item) => item.sequence === event.sequence)) {
      liveEvents.value.push(event)
    }
    void queryClient.invalidateQueries({ queryKey: ['run', props.id] })
  } catch {
    // A malformed event is ignored; the replay query remains authoritative.
  }
}

function connect(): void {
  source?.close()
  const after = events.value.at(-1)?.sequence ?? 0
  source = runEventSource(props.id, after)
  source.addEventListener('run-event', (event) =>
    appendMessage(event as MessageEvent<string>),
  )
  source.onerror = () => {
    if (run.value && terminal.has(run.value.status)) source?.close()
  }
}

function requestCancel(): void {
  confirm.require({
    header: t('runDetail.cancelTitle'),
    message: t('runDetail.cancelConfirm'),
    rejectProps: { label: t('common.back'), severity: 'secondary', outlined: true },
    acceptProps: { label: t('runDetail.cancel'), severity: 'danger' },
    accept: () => cancelMutation.mutate(),
  })
}

function exportLog(): void {
  const content = events.value
    .map((event) => `[${event.sequence}] ${event.eventType}\n${event.stdout ?? ''}`)
    .join('\n')
  const url = URL.createObjectURL(new Blob([content], { type: 'text/plain;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `ops-composer-${props.id}.log`
  link.click()
  URL.revokeObjectURL(url)
}

watch(
  () => [eventsQuery.isSuccess.value, props.id] as const,
  ([ready]) => {
    if (ready) connect()
  },
  { immediate: true },
)
watch(
  () => run.value?.status,
  (status) => {
    if (status && terminal.has(status)) source?.close()
  },
)
onBeforeUnmount(() => source?.close())
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('runDetail.title')" :description="id">
      <Button icon="pi pi-download" :label="t('runDetail.export')" severity="secondary" outlined @click="exportLog" />
      <Button icon="pi pi-refresh" :label="t('runDetail.retry')" severity="secondary" outlined :disabled="!run || !terminal.has(run.status)" :loading="retryMutation.isPending.value" @click="retryMutation.mutate()" />
      <Button icon="pi pi-times" :label="t('runDetail.cancel')" severity="danger" outlined :disabled="!canCancel" :loading="cancelMutation.isPending.value" @click="requestCancel" />
    </PageHeader>

    <Skeleton v-if="detailQuery.isPending.value" height="12rem" border-radius="16px" />
    <Message v-else-if="detailQuery.isError.value" severity="error" :closable="false">{{ t('runDetail.loadFailed') }}</Message>
    <template v-else-if="run">
      <section class="run-hero surface-card">
        <div class="run-state">
          <StatusTag :status="run.status" />
          <strong>{{ run.kind }}</strong>
          <span>{{ date(run.createdAt) }}</span>
        </div>
        <ProgressBar :value="completion" :show-value="false" />
        <dl class="run-facts">
          <div><dt>{{ t('runs.targets') }}</dt><dd>{{ targets.length }}</dd></div>
          <div><dt>{{ t('commands.timeout') }}</dt><dd>{{ run.timeoutSeconds }}s</dd></div>
          <div><dt>{{ t('commands.forks') }}</dt><dd>{{ run.forks }}</dd></div>
          <div><dt>{{ t('runDetail.worker') }}</dt><dd>{{ run.claimedBy ?? '—' }}</dd></div>
          <div><dt>{{ t('runDetail.started') }}</dt><dd>{{ date(run.startedAt) }}</dd></div>
          <div><dt>{{ t('runDetail.finished') }}</dt><dd>{{ date(run.finishedAt) }}</dd></div>
        </dl>
      </section>

      <Tabs v-model:value="activeTab" class="run-tabs">
        <TabList>
          <Tab value="summary">{{ t('runDetail.summary') }}</Tab>
          <Tab value="targets">{{ t('runDetail.targets') }}</Tab>
          <Tab value="events">{{ t('runDetail.events') }}</Tab>
        </TabList>
        <TabPanels>
          <TabPanel value="summary">
            <div class="detail-grid">
              <section>
                <h3>{{ t('runDetail.operation') }}</h3>
                <pre>{{ JSON.stringify(run.operationSpec, null, 2) }}</pre>
              </section>
              <section>
                <h3>{{ t('runDetail.result') }}</h3>
                <pre>{{ JSON.stringify(run.summary, null, 2) }}</pre>
              </section>
            </div>
            <Message v-if="run.failureMessage" severity="error" :closable="false">
              <strong>{{ run.failureCode }}</strong> — {{ run.failureMessage }}
            </Message>
          </TabPanel>
          <TabPanel value="targets">
            <DataTable :value="targets" data-key="runTargetId" striped-rows :table-props="{ 'aria-label': t('runDetail.targets') }">
              <Column field="hostName" :header="t('hosts.name')" />
              <Column field="hostAddress" :header="t('hosts.address')" />
              <Column field="status" :header="t('common.status')"><template #body="{ data }"><StatusTag :status="data.status" /></template></Column>
              <Column field="returnCode" :header="t('runDetail.returnCode')" />
              <Column field="changedCount" :header="t('runDetail.changed')" />
              <Column field="failedCount" :header="t('runDetail.failed')" />
            </DataTable>
          </TabPanel>
          <TabPanel value="events">
            <div class="event-console" role="log" aria-live="polite" :aria-label="t('runDetail.events')">
              <article v-for="event in events" :key="event.sequence">
                <header><span>#{{ event.sequence }}</span><strong>{{ event.eventType }}</strong><time>{{ date(event.createdAt) }}</time></header>
                <pre v-if="event.stdout">{{ event.stdout }}</pre>
              </article>
              <p v-if="!events.length" class="muted">{{ t('runDetail.noEvents') }}</p>
            </div>
          </TabPanel>
        </TabPanels>
      </Tabs>
    </template>
  </div>
</template>
