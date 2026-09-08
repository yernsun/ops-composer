<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Card from 'primevue/card'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Message from 'primevue/message'
import ProgressBar from 'primevue/progressbar'
import Skeleton from 'primevue/skeleton'
import Tag from 'primevue/tag'
import { useToast } from 'primevue/usetoast'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'

import PageHeader from '@/components/PageHeader.vue'
import ReauthenticateDialog from '@/features/auth/ReauthenticateDialog.vue'
import { useAuthorization } from '@/features/auth/authorization'
import { api } from '@/shared/api/client'

const { t } = useI18n()
const queryClient = useQueryClient()
const toast = useToast()
const { can, elevated } = useAuthorization()
const reauthVisible = ref(false)
const rotateAfterReauth = ref(false)
const infoQuery = useQuery({ queryKey: ['system-info'], queryFn: api.systemInfo })
const doctorQuery = useQuery({ queryKey: ['system-doctor'], queryFn: api.systemDoctor })
const keyringQuery = useQuery({
  queryKey: ['system-keyring'],
  queryFn: api.keyringStatus,
  enabled: () => can('key:rotate'),
  refetchInterval: (query) => {
    const state = query.state.data?.latestRotation?.state
    return state === 'PENDING' || state === 'RUNNING' ? 1500 : false
  },
})
const rotateMutation = useMutation({
  mutationFn: api.requestKeyRotation,
  onSuccess: async () => {
    await queryClient.invalidateQueries({ queryKey: ['system-keyring'] })
    toast.add({ severity: 'success', summary: t('system.rotationQueued'), life: 3000 })
  },
  onError: (error) => toast.add({ severity: 'error', summary: t('common.failed'), detail: error.message, life: 6000 }),
})

function requestRotation(): void {
  if (elevated.value) rotateMutation.mutate()
  else {
    rotateAfterReauth.value = true
    reauthVisible.value = true
  }
}

function continueRotation(): void {
  if (!rotateAfterReauth.value) return
  rotateAfterReauth.value = false
  rotateMutation.mutate()
}
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

    <section v-if="can('key:rotate')" class="surface-card">
      <div class="section-title">
        <div><h3>{{ t('system.keyring') }}</h3><p>{{ t('system.keyringHint') }}</p></div>
        <Button icon="pi pi-sync" :label="t('system.rotateKey')" :loading="rotateMutation.isPending.value" @click="requestRotation" />
      </div>
      <Message v-if="keyringQuery.isError.value" severity="error" :closable="false">{{ t('system.keyringFailed') }}</Message>
      <template v-else-if="keyringQuery.data.value">
        <div class="keyring-summary">
          <Tag severity="success" :value="t('system.primaryKey', { version: keyringQuery.data.value.primaryVersion })" />
          <span>{{ t('system.configuredKeys', { versions: keyringQuery.data.value.configuredVersions.join(', ') }) }}</span>
        </div>
        <DataTable :value="keyringQuery.data.value.usage" data-key="keyVersion" striped-rows :table-props="{ 'aria-label': t('system.keyUsage') }">
          <Column field="keyVersion" :header="t('credentials.version')"><template #body="{ data }">v{{ data.keyVersion }} <Tag v-if="data.primary" severity="success" :value="t('system.primary')" /></template></Column>
          <Column field="credentialCount" :header="t('nav.credentials')" />
          <Column field="mfaCount" header="MFA" />
          <Column field="systemCount" :header="t('nav.system')" />
          <Column field="runSecretCount" :header="t('system.runSecrets')" />
          <Column field="totalCount" :header="t('dashboard.total')" />
          <Column field="configured" :header="t('system.configured')"><template #body="{ data }"><Tag :severity="data.configured ? 'success' : 'danger'" :value="data.configured ? t('system.available') : t('system.missing')" /></template></Column>
        </DataTable>
        <div v-if="keyringQuery.data.value.latestRotation" class="rotation-status">
          <div class="section-title"><div><h4>{{ t('system.latestRotation') }}</h4><p><code>{{ keyringQuery.data.value.latestRotation.keyRotationJobId }}</code></p></div><Tag :severity="keyringQuery.data.value.latestRotation.state === 'SUCCEEDED' ? 'success' : keyringQuery.data.value.latestRotation.state === 'FAILED' ? 'danger' : 'info'" :value="keyringQuery.data.value.latestRotation.state" /></div>
          <ProgressBar
            v-if="keyringQuery.data.value.latestRotation.remainingCount !== null"
            :value="Math.round(100 * keyringQuery.data.value.latestRotation.processedCount / Math.max(1, keyringQuery.data.value.latestRotation.processedCount + (keyringQuery.data.value.latestRotation.remainingCount ?? 0)))"
          />
          <p>{{ t('system.rotationCounts', { processed: keyringQuery.data.value.latestRotation.processedCount, remaining: keyringQuery.data.value.latestRotation.remainingCount ?? '—' }) }}</p>
          <Message v-if="keyringQuery.data.value.latestRotation.errorCode" severity="error" :closable="false"><code>{{ keyringQuery.data.value.latestRotation.errorCode }}</code></Message>
        </div>
      </template>
    </section>
    <ReauthenticateDialog v-model:visible="reauthVisible" :reason="t('system.rotationReauth')" @success="continueRotation" />
  </div>
</template>
