<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Card from 'primevue/card'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Skeleton from 'primevue/skeleton'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'

import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import { api, type RunDto } from '@/shared/api/client'

const { t, locale } = useI18n()
const router = useRouter()
const overviewQuery = useQuery({
  queryKey: ['overview'],
  queryFn: api.overview,
  refetchInterval: 15_000,
})
const runsQuery = useQuery({
  queryKey: ['runs', 'recent'],
  queryFn: () => api.runs(8),
  refetchInterval: 10_000,
})
const stats = computed(() => [
  {
    label: t('dashboard.hosts'),
    value: overviewQuery.data.value?.hostCount ?? 0,
    detail: t('dashboard.enabledHosts', {
      count: overviewQuery.data.value?.enabledHostCount ?? 0,
    }),
    icon: 'pi pi-server',
    tone: 'blue',
  },
  {
    label: t('dashboard.activeRuns'),
    value: overviewQuery.data.value?.activeRuns ?? 0,
    detail: t('dashboard.queueHint'),
    icon: 'pi pi-spin pi-spinner',
    tone: 'cyan',
  },
  {
    label: t('dashboard.runsToday'),
    value: overviewQuery.data.value?.runsToday ?? 0,
    detail: t('dashboard.todayHint'),
    icon: 'pi pi-bolt',
    tone: 'green',
  },
  {
    label: t('dashboard.failedRuns'),
    value: overviewQuery.data.value?.failedRuns ?? 0,
    detail: t('dashboard.needsAttention'),
    icon: 'pi pi-exclamation-triangle',
    tone: 'orange',
  },
])

function date(value: string): string {
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

function openRun(event: { data: RunDto }): void {
  void router.push({ name: 'run-detail', params: { id: event.data.runId } })
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('dashboard.title')" :description="t('dashboard.description')">
      <Button
        icon="pi pi-terminal"
        :label="t('dashboard.runCommand')"
        @click="router.push('/commands')"
      />
    </PageHeader>

    <section class="stats-grid" aria-label="Overview metrics">
      <article v-for="item in stats" :key="item.label" class="stat-card">
        <div :class="['stat-icon', item.tone]"><i :class="item.icon" /></div>
        <div>
          <span>{{ item.label }}</span>
          <Skeleton v-if="overviewQuery.isPending.value" width="4rem" height="2rem" />
          <strong v-else>{{ item.value }}</strong>
          <small>{{ item.detail }}</small>
        </div>
      </article>
    </section>

    <div class="dashboard-grid">
      <Card class="health-card">
        <template #title>{{ t('dashboard.hostHealth') }}</template>
        <template #content>
          <div class="donut-wrap">
            <div
              class="status-donut"
              :style="{
                '--online': `${overviewQuery.data.value?.hostCount
                  ? ((overviewQuery.data.value.enabledHostCount / overviewQuery.data.value.hostCount) * 100)
                  : 0}%`,
              }"
            >
              <span>
                <strong>{{ overviewQuery.data.value?.hostCount ?? 0 }}</strong>
                <small>{{ t('dashboard.total') }}</small>
              </span>
            </div>
            <dl class="health-legend">
              <div><dt><i class="dot success" />{{ t('dashboard.enabled') }}</dt><dd>{{ overviewQuery.data.value?.enabledHostCount ?? 0 }}</dd></div>
              <div><dt><i class="dot neutral" />{{ t('dashboard.disabled') }}</dt><dd>{{ (overviewQuery.data.value?.hostCount ?? 0) - (overviewQuery.data.value?.enabledHostCount ?? 0) }}</dd></div>
            </dl>
          </div>
        </template>
      </Card>

      <Card class="architecture-card">
        <template #title>{{ t('dashboard.architecture') }}</template>
        <template #content>
          <div class="architecture-flow">
            <span><i class="pi pi-desktop" />API</span>
            <i class="pi pi-arrow-right" />
            <span><i class="pi pi-database" />PostgreSQL</span>
            <i class="pi pi-arrow-left" />
            <span><i class="pi pi-cog" />Worker</span>
          </div>
          <p>{{ t('dashboard.architectureHint') }}</p>
        </template>
      </Card>
    </div>

    <section class="surface-card">
      <div class="section-title">
        <div>
          <h3>{{ t('dashboard.recentRuns') }}</h3>
          <p>{{ t('dashboard.recentRunsHint') }}</p>
        </div>
        <Button
          :label="t('common.viewAll')"
          icon="pi pi-arrow-right"
          icon-pos="right"
          severity="secondary"
          text
          @click="router.push('/runs')"
        />
      </div>
      <DataTable
        :value="runsQuery.data.value ?? []"
        :loading="runsQuery.isPending.value"
        data-key="runId"
        striped-rows
        selection-mode="single"
        :table-props="{ 'aria-label': t('dashboard.recentRuns') }"
        @row-click="openRun"
      >
        <Column field="kind" :header="t('runs.kind')" />
        <Column field="status" :header="t('common.status')">
          <template #body="{ data }"><StatusTag :status="data.status" /></template>
        </Column>
        <Column :header="t('runs.targets')">
          <template #body="{ data }">{{ data.resolvedTargets.length }}</template>
        </Column>
        <Column field="createdAt" :header="t('common.createdAt')">
          <template #body="{ data }">{{ date(data.createdAt) }}</template>
        </Column>
      </DataTable>
    </section>
  </div>
</template>
