<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Card from 'primevue/card'
import Message from 'primevue/message'
import Skeleton from 'primevue/skeleton'
import { useI18n } from 'vue-i18n'

import PageHeader from '@/components/PageHeader.vue'
import { api } from '@/shared/api/client'

const { t } = useI18n()
const infoQuery = useQuery({ queryKey: ['system-info'], queryFn: api.systemInfo })
const doctorQuery = useQuery({ queryKey: ['system-doctor'], queryFn: api.systemDoctor })
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('system.title')" :description="t('system.description')">
      <Button icon="pi pi-refresh" :label="t('common.refresh')" severity="secondary" outlined @click="doctorQuery.refetch()" />
    </PageHeader>
    <div class="system-grid">
      <Card>
        <template #title>{{ t('system.runtime') }}</template>
        <template #content>
          <Skeleton v-if="infoQuery.isPending.value" height="12rem" />
          <dl v-else-if="infoQuery.data.value" class="definition-list">
            <div><dt>{{ t('system.version') }}</dt><dd>{{ infoQuery.data.value.version }}</dd></div>
            <div><dt>{{ t('system.database') }}</dt><dd>{{ infoQuery.data.value.database }}</dd></div>
            <div><dt>{{ t('system.queue') }}</dt><dd>{{ infoQuery.data.value.queue }}</dd></div>
            <div><dt>{{ t('system.playbookSourceMode') }}</dt><dd><code>{{ infoQuery.data.value.playbookSourceMode }}</code></dd></div>
            <div><dt>{{ t('system.workspace') }}</dt><dd><code>{{ infoQuery.data.value.playbookWorkspace }}</code></dd></div>
            <div><dt>{{ t('system.webShellCapacity') }}</dt><dd>{{ infoQuery.data.value.webShell.maxSessions }}</dd></div>
            <div>
              <dt>{{ t('system.webShellTimeouts') }}</dt>
              <dd>
                {{ t('system.webShellTimeoutValues', {
                  idle: Math.round(infoQuery.data.value.webShell.idleTimeoutSeconds / 60),
                  maximum: Math.round(infoQuery.data.value.webShell.maxDurationSeconds / 3600),
                }) }}
              </dd>
            </div>
          </dl>
        </template>
      </Card>
      <Card>
        <template #title>{{ t('system.foundation') }}</template>
        <template #content>
          <dl v-if="infoQuery.data.value" class="definition-list">
            <div><dt>Project Forge SHA</dt><dd><code>{{ infoQuery.data.value.projectForgeCommit.slice(0, 12) }}</code></dd></div>
            <div><dt>Template digest</dt><dd><code>{{ infoQuery.data.value.projectForgeTemplateDigest.slice(0, 24) }}…</code></dd></div>
          </dl>
        </template>
      </Card>
    </div>
    <section class="surface-card">
      <div class="section-title">
        <div><h3>{{ t('system.doctor') }}</h3><p>{{ t('system.doctorHint') }}</p></div>
      </div>
      <Message v-if="doctorQuery.isError.value" severity="error" :closable="false">{{ t('system.doctorFailed') }}</Message>
      <pre v-else>{{ JSON.stringify(doctorQuery.data.value ?? {}, null, 2) }}</pre>
    </section>
  </div>
</template>
