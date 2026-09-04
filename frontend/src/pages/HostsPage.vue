<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import Fluid from 'primevue/fluid'
import IconField from 'primevue/iconfield'
import InputIcon from 'primevue/inputicon'
import InputNumber from 'primevue/inputnumber'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'

import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import {
  ApiRequestError,
  api,
  type HostDto,
  type HostKeyScanDto,
} from '@/shared/api/client'

interface HostForm {
  hostId: string | null
  name: string
  address: string
  sshPort: number
  credentialId: string
  pythonInterpreter: string
  enabled: boolean
  description: string
  variablesText: string
  version: number
}

const { t } = useI18n()
const router = useRouter()
const queryClient = useQueryClient()
const toast = useToast()
const confirm = useConfirm()
const search = ref('')
const editVisible = ref(false)
const keysVisible = ref(false)
const keyHost = ref<HostDto | null>(null)
const scannedKeys = ref<HostKeyScanDto[]>([])
const pendingTestHostId = ref<string | null>(null)
const form = reactive<HostForm>({
  hostId: null,
  name: '',
  address: '',
  sshPort: 22,
  credentialId: '',
  pythonInterpreter: '/usr/bin/python3',
  enabled: true,
  description: '',
  variablesText: '{}',
  version: 1,
})

const hostsQuery = useQuery({ queryKey: ['hosts'], queryFn: api.hosts })
const credentialsQuery = useQuery({ queryKey: ['credentials'], queryFn: api.credentials })
const hosts = computed(() => {
  const needle = search.value.trim().toLocaleLowerCase()
  const values = hostsQuery.data.value ?? []
  if (!needle) return values
  return values.filter((host) =>
    [host.name, host.address, host.description].some((value) =>
      value.toLocaleLowerCase().includes(needle),
    ),
  )
})
const credentialNames = computed(
  () => new Map((credentialsQuery.data.value ?? []).map((item) => [item.credentialId, item.name])),
)

const saveMutation = useMutation({
  mutationFn: async () => {
    let variables: Record<string, unknown>
    try {
      variables = JSON.parse(form.variablesText) as Record<string, unknown>
    } catch {
      throw new Error(t('hosts.variablesInvalid'))
    }
    const payload = {
      name: form.name,
      address: form.address,
      sshPort: form.sshPort,
      credentialId: form.credentialId,
      pythonInterpreter: form.pythonInterpreter || null,
      enabled: form.enabled,
      description: form.description,
      variables,
    }
    if (form.hostId) {
      return api.updateHost(form.hostId, { ...payload, version: form.version })
    }
    return api.createHost(payload)
  },
  onSuccess: async () => {
    editVisible.value = false
    await queryClient.invalidateQueries({ queryKey: ['hosts'] })
    toast.add({ severity: 'success', summary: t('common.saved'), life: 2500 })
  },
  onError: (error) => {
    toast.add({ severity: 'error', summary: t('common.failed'), detail: error.message, life: 5000 })
  },
})

const testMutation = useMutation({
  mutationFn: api.testHost,
  onSuccess: (run) => void router.push({ name: 'run-detail', params: { id: run.runId } }),
  onError: (error, hostId) => {
    if (
      error instanceof ApiRequestError &&
      error.code === 'host_key_confirmation_required'
    ) {
      const host = (hostsQuery.data.value ?? []).find((item) => item.hostId === hostId)
      if (host) {
        scanKeys(host, true)
        toast.add({
          severity: 'warn',
          summary: t('hosts.hostKeys'),
          detail: t('hosts.confirmationRequired'),
          life: 8000,
        })
        return
      }
    }
    toast.add({
      severity: 'error',
      summary: t('hosts.testFailed'),
      detail: error.message,
      life: 5000,
    })
  },
})
const scanMutation = useMutation({
  mutationFn: api.scanHostKeys,
  onSuccess: (keys) => {
    scannedKeys.value = keys
    keysVisible.value = true
  },
  onError: (error) => {
    pendingTestHostId.value = null
    toast.add({
      severity: 'error',
      summary: t('hosts.scanFailed'),
      detail: error.message,
      life: 5000,
    })
  },
})
const confirmKeyMutation = useMutation({
  mutationFn: ({ hostId, key }: { hostId: string; key: HostKeyScanDto }) =>
    api.confirmHostKey(hostId, { algorithm: key.algorithm, fingerprint: key.fingerprint }),
  onSuccess: (_key, request) => {
    const resumeTest = pendingTestHostId.value === request.hostId
    pendingTestHostId.value = null
    toast.add({ severity: 'success', summary: t('hosts.keyConfirmed'), life: 2500 })
    keysVisible.value = false
    if (resumeTest) testMutation.mutate(request.hostId)
  },
  onError: (error) =>
    toast.add({
      severity: 'error',
      summary: t('hosts.keyConfirmFailed'),
      detail: error.message,
      life: 5000,
    }),
})

function resetForm(): void {
  Object.assign(form, {
    hostId: null,
    name: '',
    address: '',
    sshPort: 22,
    credentialId: credentialsQuery.data.value?.[0]?.credentialId ?? '',
    pythonInterpreter: '/usr/bin/python3',
    enabled: true,
    description: '',
    variablesText: '{}',
    version: 1,
  })
  editVisible.value = true
}

function editHost(host: HostDto): void {
  Object.assign(form, {
    hostId: host.hostId,
    name: host.name,
    address: host.address,
    sshPort: host.sshPort,
    credentialId: host.credentialId,
    pythonInterpreter: host.pythonInterpreter ?? '',
    enabled: host.enabled,
    description: host.description,
    variablesText: JSON.stringify(host.variables, null, 2),
    version: host.version,
  })
  editVisible.value = true
}

function removeHost(host: HostDto): void {
  confirm.require({
    header: t('hosts.deleteTitle'),
    message: t('hosts.deleteConfirm', { name: host.name }),
    icon: 'pi pi-exclamation-triangle',
    rejectProps: { label: t('common.cancel'), severity: 'secondary', outlined: true },
    acceptProps: { label: t('common.delete'), severity: 'danger' },
    accept: async () => {
      try {
        await api.deleteHost(host.hostId)
        await queryClient.invalidateQueries({ queryKey: ['hosts'] })
        toast.add({ severity: 'success', summary: t('common.deleted'), life: 2500 })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: t('common.failed'),
          detail: error instanceof Error ? error.message : t('common.failed'),
          life: 5000,
        })
      }
    },
  })
}

function scanKeys(host: HostDto, resumeTest = false): void {
  pendingTestHostId.value = resumeTest ? host.hostId : null
  keyHost.value = host
  scannedKeys.value = []
  scanMutation.mutate(host.hostId)
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('hosts.title')" :description="t('hosts.description')">
      <Button icon="pi pi-plus" :label="t('hosts.add')" @click="resetForm" />
    </PageHeader>
    <Message severity="info" :closable="false">
      <i class="pi pi-shield" /> {{ t('hosts.trustWorkflow') }}
    </Message>
    <section class="surface-card">
      <div class="table-toolbar">
        <IconField>
          <InputIcon class="pi pi-search" />
          <InputText v-model="search" :placeholder="t('hosts.search')" />
        </IconField>
        <Button
          icon="pi pi-refresh"
          severity="secondary"
          outlined
          :aria-label="t('common.refresh')"
          :loading="hostsQuery.isFetching.value"
          @click="hostsQuery.refetch()"
        />
      </div>
      <DataTable
        :value="hosts"
        :loading="hostsQuery.isPending.value"
        data-key="hostId"
        paginator
        :rows="10"
        :rows-per-page-options="[10, 25, 50]"
        striped-rows
        state-storage="local"
        state-key="ops-composer-hosts"
        :table-props="{ 'aria-label': t('hosts.title') }"
      >
        <Column field="name" :header="t('hosts.name')" sortable />
        <Column field="address" :header="t('hosts.address')" sortable>
          <template #body="{ data }"><code>{{ data.address }}:{{ data.sshPort }}</code></template>
        </Column>
        <Column :header="t('hosts.credential')">
          <template #body="{ data }">{{ credentialNames.get(data.credentialId) ?? '—' }}</template>
        </Column>
        <Column field="enabled" :header="t('common.status')" sortable>
          <template #body="{ data }"><StatusTag :status="data.enabled ? 'ENABLED' : 'DISABLED'" /></template>
        </Column>
        <Column :header="t('common.actions')" frozen align-frozen="right">
          <template #body="{ data }">
            <div class="row-actions">
              <Button icon="pi pi-pencil" text rounded :aria-label="t('common.edit')" @click="editHost(data)" />
              <Button icon="pi pi-shield" :label="t('hosts.scanKey')" text size="small" :loading="scanMutation.isPending.value && keyHost?.hostId === data.hostId" @click="scanKeys(data)" />
              <Button icon="pi pi-bolt" :label="t('hosts.test')" text size="small" :loading="testMutation.isPending.value" @click="testMutation.mutate(data.hostId)" />
              <Button icon="pi pi-trash" severity="danger" text rounded :aria-label="t('common.delete')" @click="removeHost(data)" />
            </div>
          </template>
        </Column>
        <template #empty>{{ t('hosts.empty') }}</template>
      </DataTable>
    </section>

    <Dialog
      v-model:visible="editVisible"
      modal
      :header="form.hostId ? t('hosts.edit') : t('hosts.add')"
      :style="{ width: 'min(760px, 94vw)' }"
    >
      <Fluid>
        <form id="host-form" class="form-grid two-columns" @submit.prevent="saveMutation.mutate()">
          <div class="field"><label for="host-name">{{ t('hosts.name') }}</label><InputText id="host-name" v-model="form.name" required /></div>
          <div class="field"><label for="host-address">{{ t('hosts.address') }}</label><InputText id="host-address" v-model="form.address" required /></div>
          <div class="field"><label for="host-port">{{ t('hosts.port') }}</label><InputNumber id="host-port" v-model="form.sshPort" :min="1" :max="65535" :use-grouping="false" /></div>
          <div class="field"><label for="host-credential">{{ t('hosts.credential') }}</label><Select id="host-credential" v-model="form.credentialId" :options="credentialsQuery.data.value ?? []" option-label="name" option-value="credentialId" /></div>
          <div class="field span-2"><label for="host-python">{{ t('hosts.python') }}</label><InputText id="host-python" v-model="form.pythonInterpreter" /></div>
          <div class="field span-2"><label for="host-description">{{ t('common.description') }}</label><Textarea id="host-description" v-model="form.description" auto-resize rows="2" /></div>
          <div class="field span-2"><label for="host-vars">{{ t('hosts.variables') }}</label><Textarea id="host-vars" v-model="form.variablesText" rows="7" class="code-input" /><small>{{ t('hosts.variablesHint') }}</small></div>
          <label class="switch-field span-2" for="host-enabled"><ToggleSwitch id="host-enabled" v-model="form.enabled" /><span>{{ t('hosts.enabled') }}</span></label>
        </form>
      </Fluid>
      <template #footer>
        <Button :label="t('common.cancel')" severity="secondary" text @click="editVisible = false" />
        <Button type="submit" form="host-form" :label="t('common.save')" icon="pi pi-check" :loading="saveMutation.isPending.value" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="keysVisible"
      modal
      :header="t('hosts.hostKeys')"
      :style="{ width: 'min(720px, 94vw)' }"
      @hide="pendingTestHostId = null"
    >
      <Message v-if="pendingTestHostId" severity="warn" :closable="false">
        {{ t('hosts.confirmationRequired') }}
      </Message>
      <p class="muted">{{ t('hosts.keyHint', { host: keyHost?.name ?? '' }) }}</p>
      <div class="key-list">
        <article v-for="key in scannedKeys" :key="key.algorithm" class="key-card">
          <div><strong>{{ key.algorithm }}</strong><code>{{ key.fingerprint }}</code></div>
          <Button
            :label="t('hosts.confirmKey')"
            icon="pi pi-shield"
            :loading="confirmKeyMutation.isPending.value"
            @click="keyHost && confirmKeyMutation.mutate({ hostId: keyHost.hostId, key })"
          />
        </article>
      </div>
    </Dialog>
  </div>
</template>
