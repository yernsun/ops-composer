<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import FileUpload from 'primevue/fileupload'
import Fluid from 'primevue/fluid'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Password from 'primevue/password'
import SelectButton from 'primevue/selectbutton'
import Tag from 'primevue/tag'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import PageHeader from '@/components/PageHeader.vue'
import ReauthenticateDialog from '@/features/auth/ReauthenticateDialog.vue'
import { useAuthorization } from '@/features/auth/authorization'
import { api, ApiRequestError, type CredentialDto, type CredentialRevisionDto } from '@/shared/api/client'

type CredentialType = CredentialDto['credentialType']

interface CredentialForm {
  credentialType: CredentialType
  name: string
  username: string
  password: string
  privateKey: string
  passphrase: string
  becomePassword: string
  becomeEnabled: boolean
  becomeMethod: string
  becomeUser: string
  description: string
}

const { t, locale } = useI18n()
const queryClient = useQueryClient()
const toast = useToast()
const confirm = useConfirm()
const { can, elevated } = useAuthorization()
const createVisible = ref(false)
const rotateVisible = ref(false)
const editVisible = ref(false)
const revisionsVisible = ref(false)
const reauthVisible = ref(false)
const pendingAction = ref<null | (() => void)>(null)
const selected = ref<CredentialDto | null>(null)
const revisions = ref<CredentialRevisionDto[]>([])
const revisionsLoading = ref(false)
const privateKeyFilename = ref('')
const keyUpload = ref<{ clear: () => void } | null>(null)
const error = ref('')
const credentialTypes: CredentialType[] = ['PASSWORD', 'SSH_PRIVATE_KEY']
const form = reactive<CredentialForm>({
  credentialType: 'PASSWORD', name: '', username: 'root', password: '', privateKey: '',
  passphrase: '', becomePassword: '', becomeEnabled: false, becomeMethod: 'sudo',
  becomeUser: 'root', description: '',
})
const rotation = reactive({ password: '', privateKey: '', passphrase: '', becomePassword: '' })
const editForm = reactive({ name: '', username: '', description: '', enabled: true, becomeEnabled: false, becomeMethod: 'sudo', becomeUser: 'root' })

const credentialsQuery = useQuery({ queryKey: ['credentials'], queryFn: api.credentials })
const canWrite = computed(() => can('credential:write'))

function publicValue(item: CredentialDto, key: string): unknown {
  return item.publicConfig?.[key]
}

function safeError(value: unknown): string {
  if (value instanceof ApiRequestError) {
    if (value.code === 'version_conflict') return t('credentials.versionConflict')
    return t(`auth.errors.${value.code}`, value.message)
  }
  return value instanceof Error ? value.message : t('common.failed')
}

function handleSensitiveError(value: unknown, retry: () => void): void {
  if (value instanceof ApiRequestError && value.code === 'reauthentication_required') {
    pendingAction.value = retry
    reauthVisible.value = true
    return
  }
  error.value = safeError(value)
  toast.add({ severity: 'error', summary: t('common.failed'), detail: error.value, life: 6000 })
}

function sensitive(action: () => void): void {
  if (elevated.value) action()
  else {
    pendingAction.value = action
    reauthVisible.value = true
  }
}

function retryAfterElevation(): void {
  const action = pendingAction.value
  pendingAction.value = null
  action?.()
}

function clearSecretState(): void {
  form.password = ''
  form.privateKey = ''
  form.passphrase = ''
  form.becomePassword = ''
  rotation.password = ''
  rotation.privateKey = ''
  rotation.passphrase = ''
  rotation.becomePassword = ''
  privateKeyFilename.value = ''
  keyUpload.value?.clear()
}

async function refresh(): Promise<void> {
  await queryClient.invalidateQueries({ queryKey: ['credentials'] })
}

const createMutation = useMutation({
  mutationFn: () => form.credentialType === 'PASSWORD'
    ? api.createCredential({
        credentialType: 'PASSWORD', name: form.name, username: form.username,
        password: form.password, becomePassword: form.becomePassword || null,
        becomeEnabled: form.becomeEnabled, becomeMethod: form.becomeMethod,
        becomeUser: form.becomeUser, description: form.description,
      })
    : api.createCredential({
        credentialType: 'SSH_PRIVATE_KEY', name: form.name, username: form.username,
        privateKey: form.privateKey, passphrase: form.passphrase || null,
        becomePassword: form.becomePassword || null, becomeEnabled: form.becomeEnabled,
        becomeMethod: form.becomeMethod, becomeUser: form.becomeUser,
        description: form.description,
      }),
  onSuccess: async () => {
    createVisible.value = false
    clearSecretState()
    await refresh()
    toast.add({ severity: 'success', summary: t('credentials.created'), life: 2500 })
  },
  onError: (value) => handleSensitiveError(value, () => createMutation.mutate()),
})

const rotateMutation = useMutation({
  mutationFn: () => {
    if (!selected.value) throw new Error(t('credentials.choose'))
    return selected.value.credentialType === 'PASSWORD'
      ? api.rotateCredential(selected.value.credentialId, {
          credentialType: 'PASSWORD', password: rotation.password,
          becomePassword: rotation.becomePassword || null,
        })
      : api.rotateCredential(selected.value.credentialId, {
          credentialType: 'SSH_PRIVATE_KEY', privateKey: rotation.privateKey,
          passphrase: rotation.passphrase || null,
          becomePassword: rotation.becomePassword || null,
        })
  },
  onSuccess: async () => {
    rotateVisible.value = false
    clearSecretState()
    await refresh()
    toast.add({ severity: 'success', summary: t('credentials.rotated'), life: 2500 })
  },
  onError: (value) => handleSensitiveError(value, () => rotateMutation.mutate()),
})

const updateMutation = useMutation({
  mutationFn: () => {
    if (!selected.value) throw new Error(t('credentials.choose'))
    return api.updateCredential(selected.value.credentialId, {
      name: editForm.name, username: editForm.username, description: editForm.description,
      enabled: editForm.enabled, becomeEnabled: editForm.becomeEnabled,
      becomeMethod: editForm.becomeMethod, becomeUser: editForm.becomeUser,
      lockVersion: selected.value.lockVersion,
    })
  },
  onSuccess: async () => {
    editVisible.value = false
    await refresh()
    toast.add({ severity: 'success', summary: t('common.saved'), life: 2500 })
  },
  onError: (value) => handleSensitiveError(value, () => updateMutation.mutate()),
})

function openCreate(): void {
  Object.assign(form, {
    credentialType: 'PASSWORD', name: '', username: 'root', password: '', privateKey: '',
    passphrase: '', becomePassword: '', becomeEnabled: false, becomeMethod: 'sudo',
    becomeUser: 'root', description: '',
  })
  error.value = ''
  createVisible.value = true
}

function openRotate(item: CredentialDto): void {
  selected.value = item
  clearSecretState()
  error.value = ''
  rotateVisible.value = true
}

function openEdit(item: CredentialDto): void {
  selected.value = item
  Object.assign(editForm, {
    name: item.name,
    username: item.username,
    description: item.description,
    enabled: item.enabled,
    becomeEnabled: Boolean(publicValue(item, 'becomeEnabled')),
    becomeMethod: String(publicValue(item, 'becomeMethod') ?? 'sudo'),
    becomeUser: String(publicValue(item, 'becomeUser') ?? 'root'),
  })
  error.value = ''
  editVisible.value = true
}

async function openRevisions(item: CredentialDto): Promise<void> {
  selected.value = item
  revisionsVisible.value = true
  revisionsLoading.value = true
  try {
    revisions.value = await api.credentialRevisions(item.credentialId)
  } catch (value) {
    error.value = safeError(value)
  } finally {
    revisionsLoading.value = false
  }
}

async function readKey(event: { files: File[] }, target: 'create' | 'rotate'): Promise<void> {
  const file = event.files[0]
  if (!file) return
  if (file.size > 1024 * 1024) {
    error.value = t('credentials.privateKeyTooLarge')
    return
  }
  const content = await file.text()
  if (target === 'create') form.privateKey = content
  else rotation.privateKey = content
  privateKeyFilename.value = file.name
}

function remove(item: CredentialDto): void {
  confirm.require({
    header: t('credentials.deleteTitle'),
    message: t('credentials.deleteConfirm', { name: item.name }),
    rejectProps: { label: t('common.cancel'), severity: 'secondary', outlined: true },
    acceptProps: { label: t('common.delete'), severity: 'danger' },
    accept: () => sensitive(async () => {
      try {
        await api.deleteCredential(item.credentialId)
        await refresh()
        toast.add({ severity: 'success', summary: t('common.deleted'), life: 2500 })
      } catch (value) {
        handleSensitiveError(value, () => remove(item))
      }
    }),
  })
}

function formatDate(value: unknown): string {
  if (typeof value !== 'string') return String(value ?? '—')
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('credentials.title')" :description="t('credentials.description')">
      <Button v-if="canWrite" icon="pi pi-plus" :label="t('credentials.add')" @click="openCreate" />
    </PageHeader>
    <Message v-if="error" severity="error" closable @close="error = ''">{{ error }}</Message>
    <section class="surface-card">
      <DataTable :value="credentialsQuery.data.value ?? []" :loading="credentialsQuery.isPending.value" data-key="credentialId" paginator :rows="10" striped-rows state-storage="local" state-key="ops-composer-credentials" :table-props="{ 'aria-label': t('credentials.title') }">
        <Column field="name" :header="t('credentials.name')" sortable><template #body="{ data }"><div class="table-primary"><strong>{{ data.name }}</strong><small>{{ data.description }}</small></div></template></Column>
        <Column field="credentialType" :header="t('credentials.type')"><template #body="{ data }"><Tag :icon="data.credentialType === 'SSH_PRIVATE_KEY' ? 'pi pi-key' : 'pi pi-lock'" :value="t(`credentials.types.${data.credentialType}`)" severity="info" /></template></Column>
        <Column field="username" :header="t('credentials.username')" />
        <Column :header="t('credentials.keyMetadata')"><template #body="{ data }"><div v-if="data.credentialType === 'SSH_PRIVATE_KEY'" class="table-primary"><span>{{ publicValue(data, 'keyAlgorithm') }} / {{ publicValue(data, 'keyBits') }}</span><code>{{ publicValue(data, 'publicKeyFingerprint') }}</code></div><span v-else>—</span></template></Column>
        <Column field="currentVersion" :header="t('credentials.version')"><template #body="{ data }">v{{ data.currentVersion }}</template></Column>
        <Column field="enabled" :header="t('common.status')"><template #body="{ data }"><Tag :severity="data.enabled ? 'success' : 'secondary'" :value="data.enabled ? t('status.ENABLED') : t('status.DISABLED')" /></template></Column>
        <Column :header="t('common.actions')">
          <template #body="{ data }">
            <div class="row-actions">
              <Button icon="pi pi-history" text rounded :aria-label="t('credentials.revisions')" @click="openRevisions(data)" />
              <template v-if="canWrite">
                <Button icon="pi pi-pencil" text rounded :aria-label="t('common.edit')" @click="openEdit(data)" />
                <Button icon="pi pi-sync" text rounded :aria-label="t('credentials.rotate')" @click="openRotate(data)" />
                <Button icon="pi pi-trash" severity="danger" text rounded :aria-label="t('common.delete')" @click="remove(data)" />
              </template>
            </div>
          </template>
        </Column>
        <template #empty>{{ t('credentials.empty') }}</template>
      </DataTable>
      <p class="security-note"><i class="pi pi-lock" />{{ t('credentials.securityNote') }}</p>
    </section>

    <Dialog v-model:visible="createVisible" modal :header="t('credentials.add')" :style="{ width: 'min(820px, 96vw)' }" @hide="clearSecretState">
      <Fluid>
        <form id="credential-form" class="form-grid two-columns" @submit.prevent="sensitive(() => createMutation.mutate())">
          <div class="field span-2"><label>{{ t('credentials.type') }}</label><SelectButton v-model="form.credentialType" :options="credentialTypes" :allow-empty="false"><template #option="{ option }">{{ t(`credentials.types.${option}`) }}</template></SelectButton></div>
          <div class="field"><label for="credential-name">{{ t('credentials.name') }}</label><InputText id="credential-name" v-model="form.name" required /></div>
          <div class="field"><label for="credential-user">{{ t('credentials.username') }}</label><InputText id="credential-user" v-model="form.username" required autocomplete="off" /></div>
          <div v-if="form.credentialType === 'PASSWORD'" class="field span-2"><label for="credential-password">{{ t('credentials.sshPassword') }}</label><Password id="credential-password" v-model="form.password" :feedback="false" toggle-mask required autocomplete="new-password" /></div>
          <template v-else>
            <div class="field span-2"><label>{{ t('credentials.privateKey') }}</label><FileUpload ref="keyUpload" mode="basic" name="privateKey" accept=".pem,.key,text/plain" :max-file-size="1048576" custom-upload :auto="false" :choose-label="t('credentials.choosePrivateKey')" @select="readKey($event, 'create')" /><small>{{ privateKeyFilename || t('credentials.privateKeyLocalHint') }}</small></div>
            <div class="field span-2"><label for="credential-passphrase">{{ t('credentials.passphrase') }}</label><Password id="credential-passphrase" v-model="form.passphrase" :feedback="false" toggle-mask autocomplete="new-password" /></div>
          </template>
          <div class="field span-2"><label for="credential-become-password">{{ t('credentials.becomePassword') }}</label><Password id="credential-become-password" v-model="form.becomePassword" :feedback="false" toggle-mask autocomplete="new-password" /></div>
          <label class="switch-field span-2" for="credential-become"><ToggleSwitch id="credential-become" v-model="form.becomeEnabled" /><span>{{ t('credentials.becomeEnabled') }}</span></label>
          <div class="field"><label for="credential-method">{{ t('credentials.becomeMethod') }}</label><InputText id="credential-method" v-model="form.becomeMethod" /></div>
          <div class="field"><label for="credential-become-user">{{ t('credentials.becomeUser') }}</label><InputText id="credential-become-user" v-model="form.becomeUser" /></div>
          <div class="field span-2"><label for="credential-description">{{ t('common.description') }}</label><Textarea id="credential-description" v-model="form.description" auto-resize rows="2" /></div>
          <Message v-if="error" class="span-2" severity="error" :closable="false">{{ error }}</Message>
        </form>
      </Fluid>
      <template #footer><Button :label="t('common.cancel')" severity="secondary" text @click="createVisible = false" /><Button type="submit" form="credential-form" :label="t('common.save')" icon="pi pi-check" :loading="createMutation.isPending.value" :disabled="form.credentialType === 'PASSWORD' ? !form.password : !form.privateKey" /></template>
    </Dialog>

    <Dialog v-model:visible="rotateVisible" modal :header="t('credentials.rotateTitle', { name: selected?.name ?? '' })" :style="{ width: 'min(620px, 94vw)' }" @hide="clearSecretState">
      <Fluid>
        <form id="rotate-form" class="form-stack" @submit.prevent="sensitive(() => rotateMutation.mutate())">
          <Message severity="info" :closable="false">{{ t('credentials.rotationHint') }}</Message>
          <div v-if="selected?.credentialType === 'PASSWORD'" class="field"><label for="rotation-password">{{ t('credentials.sshPassword') }}</label><Password id="rotation-password" v-model="rotation.password" :feedback="false" toggle-mask required autocomplete="new-password" /></div>
          <template v-else>
            <div class="field"><label>{{ t('credentials.privateKey') }}</label><FileUpload mode="basic" name="rotationPrivateKey" accept=".pem,.key,text/plain" :max-file-size="1048576" custom-upload :auto="false" :choose-label="t('credentials.choosePrivateKey')" @select="readKey($event, 'rotate')" /></div>
            <div class="field"><label for="rotation-passphrase">{{ t('credentials.passphrase') }}</label><Password id="rotation-passphrase" v-model="rotation.passphrase" :feedback="false" toggle-mask autocomplete="new-password" /></div>
          </template>
          <div class="field"><label for="rotation-become">{{ t('credentials.becomePassword') }}</label><Password id="rotation-become" v-model="rotation.becomePassword" :feedback="false" toggle-mask autocomplete="new-password" /></div>
          <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
        </form>
      </Fluid>
      <template #footer><Button :label="t('common.cancel')" severity="secondary" text @click="rotateVisible = false" /><Button type="submit" form="rotate-form" :label="t('credentials.rotate')" icon="pi pi-sync" :loading="rotateMutation.isPending.value" :disabled="selected?.credentialType === 'PASSWORD' ? !rotation.password : !rotation.privateKey" /></template>
    </Dialog>

    <Dialog v-model:visible="editVisible" modal :header="t('credentials.editTitle', { name: selected?.name ?? '' })" :style="{ width: 'min(720px, 95vw)' }">
      <Fluid>
        <form id="edit-credential-form" class="form-grid two-columns" @submit.prevent="sensitive(() => updateMutation.mutate())">
          <div class="field"><label for="edit-credential-name">{{ t('credentials.name') }}</label><InputText id="edit-credential-name" v-model="editForm.name" required /></div>
          <div class="field"><label for="edit-credential-user">{{ t('credentials.username') }}</label><InputText id="edit-credential-user" v-model="editForm.username" required /></div>
          <label class="switch-field span-2" for="edit-credential-enabled"><ToggleSwitch id="edit-credential-enabled" v-model="editForm.enabled" /><span>{{ t('credentials.enabled') }}</span></label>
          <label class="switch-field span-2" for="edit-credential-become"><ToggleSwitch id="edit-credential-become" v-model="editForm.becomeEnabled" /><span>{{ t('credentials.becomeEnabled') }}</span></label>
          <div class="field"><label for="edit-credential-method">{{ t('credentials.becomeMethod') }}</label><InputText id="edit-credential-method" v-model="editForm.becomeMethod" /></div>
          <div class="field"><label for="edit-credential-become-user">{{ t('credentials.becomeUser') }}</label><InputText id="edit-credential-become-user" v-model="editForm.becomeUser" /></div>
          <div class="field span-2"><label for="edit-credential-description">{{ t('common.description') }}</label><Textarea id="edit-credential-description" v-model="editForm.description" rows="2" auto-resize /></div>
          <Message v-if="error" class="span-2" severity="error" :closable="false">{{ error }}</Message>
        </form>
      </Fluid>
      <template #footer><Button :label="t('common.cancel')" severity="secondary" text @click="editVisible = false" /><Button type="submit" form="edit-credential-form" icon="pi pi-save" :label="t('common.save')" :loading="updateMutation.isPending.value" /></template>
    </Dialog>

    <Dialog v-model:visible="revisionsVisible" modal :header="t('credentials.revisionsTitle', { name: selected?.name ?? '' })" :style="{ width: 'min(700px, 95vw)' }">
      <DataTable :value="revisions" :loading="revisionsLoading" data-key="version" striped-rows><Column field="version" :header="t('credentials.version')"><template #body="{ data }">v{{ data.version }}</template></Column><Column field="encryptionKeyVersion" :header="t('credentials.encryptionKeyVersion')"><template #body="{ data }">v{{ data.encryptionKeyVersion }}</template></Column><Column field="createdAt" :header="t('common.createdAt')"><template #body="{ data }">{{ formatDate(data.createdAt) }}</template></Column></DataTable>
    </Dialog>

    <ReauthenticateDialog v-model:visible="reauthVisible" :reason="t('credentials.reauthenticationHint')" @success="retryAfterElevation" />
  </div>
</template>
