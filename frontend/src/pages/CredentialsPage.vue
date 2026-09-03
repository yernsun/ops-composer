<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import Fluid from 'primevue/fluid'
import InputText from 'primevue/inputtext'
import Password from 'primevue/password'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import { api, type CredentialDto } from '@/shared/api/client'

interface CredentialForm {
  name: string
  username: string
  password: string
  becomePassword: string
  becomeEnabled: boolean
  becomeMethod: string
  becomeUser: string
  description: string
}

const { t } = useI18n()
const queryClient = useQueryClient()
const toast = useToast()
const confirm = useConfirm()
const createVisible = ref(false)
const rotateVisible = ref(false)
const rotating = ref<CredentialDto | null>(null)
const form = reactive<CredentialForm>({
  name: '',
  username: 'root',
  password: '',
  becomePassword: '',
  becomeEnabled: false,
  becomeMethod: 'sudo',
  becomeUser: 'root',
  description: '',
})
const rotation = reactive({ password: '', becomePassword: '' })
const credentialsQuery = useQuery({ queryKey: ['credentials'], queryFn: api.credentials })
const createMutation = useMutation({
  mutationFn: () =>
    api.createCredential({
      name: form.name,
      username: form.username,
      password: form.password,
      becomePassword: form.becomePassword || null,
      becomeEnabled: form.becomeEnabled,
      becomeMethod: form.becomeMethod,
      becomeUser: form.becomeUser,
      description: form.description,
    }),
  onSuccess: async () => {
    createVisible.value = false
    form.password = ''
    form.becomePassword = ''
    await queryClient.invalidateQueries({ queryKey: ['credentials'] })
    toast.add({ severity: 'success', summary: t('credentials.created'), life: 2500 })
  },
  onError: (error) =>
    toast.add({ severity: 'error', summary: t('common.failed'), detail: error.message, life: 5000 }),
})
const rotateMutation = useMutation({
  mutationFn: () => {
    if (!rotating.value) throw new Error(t('credentials.choose'))
    return api.rotateCredential(rotating.value.credentialId, {
      password: rotation.password,
      becomePassword: rotation.becomePassword || null,
    })
  },
  onSuccess: async () => {
    rotateVisible.value = false
    rotation.password = ''
    rotation.becomePassword = ''
    await queryClient.invalidateQueries({ queryKey: ['credentials'] })
    toast.add({ severity: 'success', summary: t('credentials.rotated'), life: 2500 })
  },
})

function openCreate(): void {
  Object.assign(form, {
    name: '',
    username: 'root',
    password: '',
    becomePassword: '',
    becomeEnabled: false,
    becomeMethod: 'sudo',
    becomeUser: 'root',
    description: '',
  })
  createVisible.value = true
}

function openRotate(item: CredentialDto): void {
  rotating.value = item
  rotation.password = ''
  rotation.becomePassword = ''
  rotateVisible.value = true
}

function remove(item: CredentialDto): void {
  confirm.require({
    header: t('credentials.deleteTitle'),
    message: t('credentials.deleteConfirm', { name: item.name }),
    rejectProps: { label: t('common.cancel'), severity: 'secondary', outlined: true },
    acceptProps: { label: t('common.delete'), severity: 'danger' },
    accept: async () => {
      await api.deleteCredential(item.credentialId)
      await queryClient.invalidateQueries({ queryKey: ['credentials'] })
      toast.add({ severity: 'success', summary: t('common.deleted'), life: 2500 })
    },
  })
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('credentials.title')" :description="t('credentials.description')">
      <Button icon="pi pi-plus" :label="t('credentials.add')" @click="openCreate" />
    </PageHeader>
    <section class="surface-card">
      <DataTable
        :value="credentialsQuery.data.value ?? []"
        :loading="credentialsQuery.isPending.value"
        data-key="credentialId"
        paginator
        :rows="10"
        striped-rows
        state-storage="local"
        state-key="ops-composer-credentials"
        :table-props="{ 'aria-label': t('credentials.title') }"
      >
        <Column field="name" :header="t('credentials.name')" sortable />
        <Column field="credentialType" :header="t('credentials.type')" />
        <Column field="username" :header="t('credentials.username')" />
        <Column field="currentVersion" :header="t('credentials.version')">
          <template #body="{ data }">v{{ data.currentVersion }}</template>
        </Column>
        <Column field="enabled" :header="t('common.status')">
          <template #body="{ data }"><StatusTag :status="data.enabled ? 'ENABLED' : 'DISABLED'" /></template>
        </Column>
        <Column :header="t('common.actions')">
          <template #body="{ data }">
            <div class="row-actions">
              <Button icon="pi pi-sync" text rounded :aria-label="t('credentials.rotate')" @click="openRotate(data)" />
              <Button icon="pi pi-trash" severity="danger" text rounded :aria-label="t('common.delete')" @click="remove(data)" />
            </div>
          </template>
        </Column>
        <template #empty>{{ t('credentials.empty') }}</template>
      </DataTable>
      <p class="security-note"><i class="pi pi-lock" />{{ t('credentials.securityNote') }}</p>
    </section>

    <Dialog v-model:visible="createVisible" modal :header="t('credentials.add')" :style="{ width: 'min(760px, 94vw)' }">
      <Fluid>
        <form id="credential-form" class="form-grid two-columns" @submit.prevent="createMutation.mutate()">
          <div class="field"><label for="credential-name">{{ t('credentials.name') }}</label><InputText id="credential-name" v-model="form.name" required /></div>
          <div class="field"><label for="credential-user">{{ t('credentials.username') }}</label><InputText id="credential-user" v-model="form.username" required autocomplete="off" /></div>
          <div class="field"><label for="credential-password">{{ t('credentials.sshPassword') }}</label><Password id="credential-password" v-model="form.password" :feedback="false" toggle-mask required autocomplete="new-password" /></div>
          <div class="field"><label for="credential-become-password">{{ t('credentials.becomePassword') }}</label><Password id="credential-become-password" v-model="form.becomePassword" :feedback="false" toggle-mask autocomplete="new-password" /></div>
          <label class="switch-field span-2" for="credential-become"><ToggleSwitch id="credential-become" v-model="form.becomeEnabled" /><span>{{ t('credentials.becomeEnabled') }}</span></label>
          <div class="field"><label for="credential-method">{{ t('credentials.becomeMethod') }}</label><InputText id="credential-method" v-model="form.becomeMethod" /></div>
          <div class="field"><label for="credential-become-user">{{ t('credentials.becomeUser') }}</label><InputText id="credential-become-user" v-model="form.becomeUser" /></div>
          <div class="field span-2"><label for="credential-description">{{ t('common.description') }}</label><Textarea id="credential-description" v-model="form.description" auto-resize rows="2" /></div>
        </form>
      </Fluid>
      <template #footer>
        <Button :label="t('common.cancel')" severity="secondary" text @click="createVisible = false" />
        <Button type="submit" form="credential-form" :label="t('common.save')" icon="pi pi-check" :loading="createMutation.isPending.value" />
      </template>
    </Dialog>

    <Dialog v-model:visible="rotateVisible" modal :header="t('credentials.rotateTitle', { name: rotating?.name ?? '' })" :style="{ width: 'min(560px, 94vw)' }">
      <Fluid>
        <form id="rotate-form" class="form-grid" @submit.prevent="rotateMutation.mutate()">
          <p class="muted">{{ t('credentials.rotationHint') }}</p>
          <div class="field"><label for="rotation-password">{{ t('credentials.sshPassword') }}</label><Password id="rotation-password" v-model="rotation.password" :feedback="false" toggle-mask required autocomplete="new-password" /></div>
          <div class="field"><label for="rotation-become">{{ t('credentials.becomePassword') }}</label><Password id="rotation-become" v-model="rotation.becomePassword" :feedback="false" toggle-mask autocomplete="new-password" /></div>
        </form>
      </Fluid>
      <template #footer>
        <Button :label="t('common.cancel')" severity="secondary" text @click="rotateVisible = false" />
        <Button type="submit" form="rotate-form" :label="t('credentials.rotate')" icon="pi pi-sync" :loading="rotateMutation.isPending.value" />
      </template>
    </Dialog>
  </div>
</template>
