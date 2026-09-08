<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Checkbox from 'primevue/checkbox'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import Fluid from 'primevue/fluid'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Select from 'primevue/select'
import Tag from 'primevue/tag'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import PageHeader from '@/components/PageHeader.vue'
import ReauthenticateDialog from '@/features/auth/ReauthenticateDialog.vue'
import { useAuthorization } from '@/features/auth/authorization'
import { authQueryKeys } from '@/features/auth/session'
import { api, ApiRequestError, type CreatedUserDto, type UserDto } from '@/shared/api/client'

type UserRole = UserDto['role']
type UserStatus = UserDto['status']

const { t, locale } = useI18n()
const queryClient = useQueryClient()
const toast = useToast()
const confirm = useConfirm()
const { session, elevated, can } = useAuthorization()
const usersQuery = useQuery({ queryKey: ['users'], queryFn: api.users, enabled: () => can('user:read') })
const createVisible = ref(false)
const editVisible = ref(false)
const activationVisible = ref(false)
const activationAcknowledged = ref(false)
const oneTimeActivation = ref<CreatedUserDto | null>(null)
const selected = ref<UserDto | null>(null)
const reauthVisible = ref(false)
const pendingAction = ref<null | (() => void)>(null)
const error = ref('')
const createForm = reactive<{ username: string; role: UserRole }>({ username: '', role: 'OPERATOR' })
const editForm = reactive<{ role: UserRole; status: UserStatus }>({ role: 'OPERATOR', status: 'ACTIVE' })
const roles: UserRole[] = ['OWNER', 'ADMIN', 'OPERATOR', 'AUDITOR']
const statuses: UserStatus[] = ['PENDING_ACTIVATION', 'ACTIVE', 'DISABLED']

function safeError(value: unknown): string {
  if (value instanceof ApiRequestError) {
    if (value.code === 'last_owner_required') return t('users.lastOwner')
    if (value.code === 'version_conflict') return t('users.versionConflict')
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

async function refresh(): Promise<void> {
  await queryClient.invalidateQueries({ queryKey: ['users'] })
  await queryClient.invalidateQueries({ queryKey: authQueryKeys.session })
}

const createMutation = useMutation({
  mutationFn: () => api.createUser({ username: createForm.username.trim(), role: createForm.role }),
  onSuccess: async (result) => {
    createVisible.value = false
    createForm.username = ''
    oneTimeActivation.value = result
    activationAcknowledged.value = false
    activationVisible.value = true
    await refresh()
  },
  onError: (value) => handleSensitiveError(value, () => createMutation.mutate()),
})

const updateMutation = useMutation({
  mutationFn: () => {
    if (!selected.value) throw new Error(t('users.choose'))
    return api.updateUser(selected.value.userId, {
      role: editForm.role,
      status: editForm.status,
      expectedVersion: selected.value.version,
    })
  },
  onSuccess: async () => {
    editVisible.value = false
    await refresh()
    toast.add({ severity: 'success', summary: t('common.saved'), life: 2500 })
  },
  onError: (value) => handleSensitiveError(value, () => updateMutation.mutate()),
})

const reissueMutation = useMutation({
  mutationFn: (user: UserDto) => api.reissueUserActivation(user.userId),
  onSuccess: async (result) => {
    oneTimeActivation.value = result
    activationAcknowledged.value = false
    activationVisible.value = true
    await refresh()
  },
  onError: (value, user) => handleSensitiveError(value, () => reissueMutation.mutate(user)),
})

const resetMfaMutation = useMutation({
  mutationFn: (user: UserDto) => api.resetUserMfa(user.userId),
  onSuccess: async () => {
    await refresh()
    toast.add({ severity: 'success', summary: t('users.mfaResetDone'), life: 3000 })
  },
  onError: (value, user) => handleSensitiveError(value, () => resetMfaMutation.mutate(user)),
})

function openCreate(): void {
  createForm.username = ''
  createForm.role = 'OPERATOR'
  error.value = ''
  createVisible.value = true
}

function openEdit(user: UserDto): void {
  selected.value = user
  editForm.role = user.role
  editForm.status = user.status
  error.value = ''
  editVisible.value = true
}

function confirmMfaReset(user: UserDto): void {
  confirm.require({
    header: t('users.resetMfa'),
    message: t('users.resetMfaConfirm', { name: user.username }),
    rejectProps: { label: t('common.cancel'), severity: 'secondary', outlined: true },
    acceptProps: { label: t('users.resetMfa'), severity: 'danger' },
    accept: () => sensitive(() => resetMfaMutation.mutate(user)),
  })
}

function closeActivation(): void {
  if (!activationAcknowledged.value) return
  oneTimeActivation.value = null
  activationVisible.value = false
}

function formatDate(value: string | null): string {
  if (!value) return '—'
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('users.title')" :description="t('users.description')">
      <Button v-if="can('user:manage')" icon="pi pi-user-plus" :label="t('users.add')" @click="sensitive(openCreate)" />
    </PageHeader>
    <Message v-if="session && !session.totpPolicyEnabled" severity="warn" :closable="false" role="status">
      {{ t('users.totpPolicyDisabled') }}
    </Message>
    <Message v-if="!can('user:read')" severity="error" :closable="false">{{ t('auth.errors.permission_denied') }}</Message>
    <Message v-if="error" severity="error" closable @close="error = ''">{{ error }}</Message>
    <section v-if="can('user:read')" class="surface-card">
      <DataTable :value="usersQuery.data.value ?? []" :loading="usersQuery.isPending.value" data-key="userId" paginator :rows="20" striped-rows :table-props="{ 'aria-label': t('users.title') }">
        <Column field="username" :header="t('auth.username')" sortable>
          <template #body="{ data }"><strong>{{ data.username }}</strong><small v-if="data.userId === session?.userId" class="current-user">{{ t('users.you') }}</small></template>
        </Column>
        <Column field="role" :header="t('users.role')" sortable><template #body="{ data }"><Tag :value="t(`roles.${data.role}`)" severity="info" /></template></Column>
        <Column field="status" :header="t('common.status')" sortable><template #body="{ data }"><Tag :value="t(`status.${data.status}`)" :severity="data.status === 'ACTIVE' ? 'success' : data.status === 'DISABLED' ? 'danger' : 'warn'" /></template></Column>
        <Column field="mfaEnrollmentRequired" :header="t('security.mfa')"><template #body="{ data }">{{ session?.totpPolicyEnabled ? (data.mfaEnrollmentRequired ? t('users.enrollmentRequired') : t('users.enrollmentComplete')) : (data.mfaEnrollmentRequired ? t('users.requiredWhenEnabled') : t('security.policyDisabled')) }}</template></Column>
        <Column field="updatedAt" :header="t('playbooks.updatedAt')" sortable><template #body="{ data }">{{ formatDate(data.updatedAt) }}</template></Column>
        <Column v-if="can('user:manage')" :header="t('common.actions')">
          <template #body="{ data }">
            <div class="row-actions">
              <Button icon="pi pi-pencil" text rounded :aria-label="t('common.edit')" @click="sensitive(() => openEdit(data))" />
              <Button v-if="data.status === 'PENDING_ACTIVATION'" icon="pi pi-send" text rounded :aria-label="t('users.reissueActivation')" @click="sensitive(() => reissueMutation.mutate(data))" />
              <Button v-if="data.status === 'ACTIVE' && data.userId !== session?.userId" icon="pi pi-shield" severity="warn" text rounded :aria-label="t('users.resetMfa')" @click="confirmMfaReset(data)" />
            </div>
          </template>
        </Column>
        <template #empty>{{ t('users.empty') }}</template>
      </DataTable>
    </section>

    <Dialog v-model:visible="createVisible" modal :header="t('users.add')" :style="{ width: 'min(560px, 94vw)' }">
      <Fluid>
        <form id="create-user-form" class="form-stack" @submit.prevent="createMutation.mutate()">
          <div class="field"><label for="new-user-name">{{ t('auth.username') }}</label><InputText id="new-user-name" v-model="createForm.username" required maxlength="64" autocomplete="off" /></div>
          <div class="field"><label for="new-user-role">{{ t('users.role') }}</label><Select id="new-user-role" v-model="createForm.role" :options="roles" :option-label="(role) => t(`roles.${role}`)" /></div>
          <Message severity="info" :closable="false">{{ t('users.activationHint') }}</Message>
          <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
        </form>
      </Fluid>
      <template #footer><Button :label="t('common.cancel')" severity="secondary" text @click="createVisible = false" /><Button type="submit" form="create-user-form" icon="pi pi-user-plus" :label="t('users.create')" :loading="createMutation.isPending.value" /></template>
    </Dialog>

    <Dialog v-model:visible="editVisible" modal :header="t('users.editTitle', { name: selected?.username ?? '' })" :style="{ width: 'min(560px, 94vw)' }">
      <Fluid>
        <form id="edit-user-form" class="form-stack" @submit.prevent="updateMutation.mutate()">
          <div class="field"><label for="edit-user-role">{{ t('users.role') }}</label><Select id="edit-user-role" v-model="editForm.role" :options="roles" :option-label="(role) => t(`roles.${role}`)" /></div>
          <div class="field"><label for="edit-user-status">{{ t('common.status') }}</label><Select id="edit-user-status" v-model="editForm.status" :options="statuses" :option-label="(value) => t(`status.${value}`)" /></div>
          <Message severity="warn" :closable="false">{{ t('users.sessionRevocationHint') }}</Message>
          <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
        </form>
      </Fluid>
      <template #footer><Button :label="t('common.cancel')" severity="secondary" text @click="editVisible = false" /><Button type="submit" form="edit-user-form" icon="pi pi-save" :label="t('common.save')" :loading="updateMutation.isPending.value" /></template>
    </Dialog>

    <Dialog :visible="activationVisible" modal :closable="false" :header="t('users.activationTitle')" :style="{ width: 'min(680px, 95vw)' }">
      <div class="form-stack">
        <Message severity="warn" :closable="false">{{ t('users.activationOneTime') }}</Message>
        <div class="one-time-secret"><span>{{ oneTimeActivation?.user.username }}</span><code class="break-all">{{ oneTimeActivation?.activationCode }}</code><small>{{ t('users.expiresAt', { time: formatDate(oneTimeActivation?.activationExpiresAt ?? null) }) }}</small></div>
        <label class="switch-field" for="activation-saved"><Checkbox id="activation-saved" v-model="activationAcknowledged" binary /><span>{{ t('users.activationSaved') }}</span></label>
      </div>
      <template #footer><Button :label="t('auth.continue')" :disabled="!activationAcknowledged" @click="closeActivation" /></template>
    </Dialog>

    <ReauthenticateDialog v-model:visible="reauthVisible" :reason="t('users.reauthenticationHint')" @success="retryAfterElevation" />
  </div>
</template>
