<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Card from 'primevue/card'
import Checkbox from 'primevue/checkbox'
import Dialog from 'primevue/dialog'
import Fluid from 'primevue/fluid'
import Message from 'primevue/message'
import Password from 'primevue/password'
import Tag from 'primevue/tag'
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import PageHeader from '@/components/PageHeader.vue'
import ReauthenticateDialog from '@/features/auth/ReauthenticateDialog.vue'
import { useAuthorization } from '@/features/auth/authorization'
import { applySessionTransition, authQueryKeys } from '@/features/auth/session'
import { api, ApiRequestError, type AuthChallengeDto } from '@/shared/api/client'

const { t, locale } = useI18n()
const queryClient = useQueryClient()
const { session, elevated } = useAuthorization()
const securityQuery = useQuery({ queryKey: ['auth', 'security'], queryFn: api.securityStatus })
const enrollment = ref<AuthChallengeDto | null>(null)
const enrollmentCode = ref('')
const enrollmentVisible = ref(false)
const recoveryCodes = ref<string[]>([])
const recoveryVisible = ref(false)
const recoveryAcknowledged = ref(false)
const reauthVisible = ref(false)
const pendingSensitiveAction = ref<null | (() => void)>(null)
const passwordVisible = ref(false)
const passwordForm = reactive({ currentPassword: '', newPassword: '', confirmPassword: '', mfaValue: '' })
const error = ref('')
const totpPolicyEnabled = computed(
  () => securityQuery.data.value?.totpPolicyEnabled ?? session.value?.totpPolicyEnabled ?? true,
)

const elevatedText = computed(() => {
  const value = securityQuery.data.value?.elevatedUntil
  if (!value || new Date(value).getTime() <= Date.now()) return t('security.notElevated')
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value))
})

function safeError(value: unknown): string {
  if (value instanceof ApiRequestError) return t(`auth.errors.${value.code}`, value.message)
  return value instanceof Error ? value.message : t('common.failed')
}

function requireElevation(action: () => void): void {
  if (elevated.value) {
    action()
    return
  }
  pendingSensitiveAction.value = action
  reauthVisible.value = true
}

function retryAfterElevation(): void {
  const action = pendingSensitiveAction.value
  pendingSensitiveAction.value = null
  action?.()
}

const beginEnrollmentMutation = useMutation({
  mutationFn: api.beginMfaEnrollment,
  onSuccess: (result) => {
    enrollment.value = result
    enrollmentCode.value = ''
    error.value = ''
    enrollmentVisible.value = true
  },
  onError: (value) => { error.value = safeError(value) },
})

const confirmEnrollmentMutation = useMutation({
  mutationFn: () => api.confirmMfaEnrollment(enrollmentCode.value),
  onSuccess: async (result) => {
    enrollmentVisible.value = false
    enrollment.value = null
    enrollmentCode.value = ''
    recoveryCodes.value = result.recoveryCodes ?? []
    recoveryAcknowledged.value = false
    recoveryVisible.value = true
    await applySessionTransition(queryClient, result.session)
    await queryClient.invalidateQueries({ queryKey: ['auth', 'security'] })
  },
  onError: (value) => { error.value = safeError(value) },
})

const regenerateMutation = useMutation({
  mutationFn: api.regenerateRecoveryCodes,
  onSuccess: async (result) => {
    recoveryCodes.value = result.recoveryCodes
    recoveryAcknowledged.value = false
    recoveryVisible.value = true
    await queryClient.invalidateQueries({ queryKey: ['auth', 'security'] })
  },
  onError: (value) => {
    if (value instanceof ApiRequestError && value.code === 'reauthentication_required') {
      requireElevation(() => regenerateMutation.mutate())
      return
    }
    error.value = safeError(value)
  },
})

const passwordMutation = useMutation({
  mutationFn: () => {
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      throw new Error(t('security.passwordMismatch'))
    }
    return api.changePassword({
      currentPassword: passwordForm.currentPassword,
      newPassword: passwordForm.newPassword,
      mfaValue: passwordForm.mfaValue || null,
    })
  },
  onSuccess: async () => {
    Object.assign(passwordForm, { currentPassword: '', newPassword: '', confirmPassword: '', mfaValue: '' })
    passwordVisible.value = false
    queryClient.setQueryData(authQueryKeys.session, null)
    await queryClient.invalidateQueries({ queryKey: authQueryKeys.session })
  },
  onError: (value) => { error.value = safeError(value) },
})

function closeRecovery(): void {
  if (!recoveryAcknowledged.value) return
  recoveryCodes.value = []
  recoveryVisible.value = false
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('security.title')" :description="t('security.description')" />
    <Message v-if="!totpPolicyEnabled" severity="warn" :closable="false" role="status">
      {{ t('security.totpPolicyDisabled') }}
    </Message>
    <Message v-if="error" severity="error" closable @close="error = ''">{{ error }}</Message>

    <div class="system-grid">
      <Card>
        <template #title>{{ t('security.account') }}</template>
        <template #content>
          <dl class="definition-list">
            <div><dt>{{ t('auth.username') }}</dt><dd>{{ session?.username }}</dd></div>
            <div><dt>{{ t('users.role') }}</dt><dd><Tag :value="t(`roles.${session?.role}`)" /></dd></div>
            <div><dt>{{ t('security.mfa') }}</dt><dd><Tag :severity="!totpPolicyEnabled ? 'warn' : securityQuery.data.value?.mfaEnabled ? 'success' : 'warn'" :value="!totpPolicyEnabled ? (securityQuery.data.value?.mfaEnabled ? t('security.retained') : t('security.policyDisabled')) : securityQuery.data.value?.mfaEnabled ? t('security.enabled') : t('security.disabled')" /></dd></div>
            <div v-if="totpPolicyEnabled"><dt>{{ t('security.recoveryRemaining') }}</dt><dd>{{ securityQuery.data.value?.unusedRecoveryCodes ?? '—' }}</dd></div>
            <div><dt>{{ t('security.elevation') }}</dt><dd>{{ elevatedText }}</dd></div>
          </dl>
        </template>
      </Card>
      <Card>
        <template #title>{{ t('security.actions') }}</template>
        <template #content>
          <div class="button-stack">
            <Button v-if="totpPolicyEnabled && !securityQuery.data.value?.mfaEnabled" icon="pi pi-mobile" :label="t('security.enableMfa')" @click="beginEnrollmentMutation.mutate()" />
            <Button v-else-if="totpPolicyEnabled" icon="pi pi-refresh" severity="secondary" outlined :label="t('security.regenerateRecovery')" @click="requireElevation(() => regenerateMutation.mutate())" />
            <Button icon="pi pi-key" severity="secondary" outlined :label="t('security.changePassword')" @click="passwordVisible = true" />
            <Button icon="pi pi-shield" severity="secondary" outlined :label="t('auth.reauthenticate')" @click="reauthVisible = true" />
          </div>
        </template>
      </Card>
    </div>

    <Dialog v-model:visible="enrollmentVisible" modal :header="t('security.enrollTitle')" :style="{ width: 'min(640px, 95vw)' }">
      <div class="form-stack">
        <Message severity="warn" :closable="false">{{ t('security.enrollOneTime') }}</Message>
        <div class="one-time-secret"><span>{{ t('auth.totpSecret') }}</span><code>{{ enrollment?.enrollmentSecret }}</code></div>
        <div class="one-time-secret"><span>{{ t('security.otpauthUri') }}</span><code class="break-all">{{ enrollment?.otpauthUri }}</code></div>
        <Fluid><div class="field"><label for="security-enroll-code">{{ t('auth.mfaValue') }}</label><Password id="security-enroll-code" v-model="enrollmentCode" :feedback="false" toggle-mask autocomplete="one-time-code" /></div></Fluid>
        <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
      </div>
      <template #footer>
        <Button :label="t('common.cancel')" severity="secondary" text @click="enrollmentVisible = false" />
        <Button icon="pi pi-check" :label="t('auth.verify')" :loading="confirmEnrollmentMutation.isPending.value" :disabled="enrollmentCode.trim().length < 6" @click="confirmEnrollmentMutation.mutate()" />
      </template>
    </Dialog>

    <Dialog :visible="recoveryVisible" modal :closable="false" :header="t('auth.recoveryTitle')" :style="{ width: 'min(640px, 95vw)' }">
      <div class="form-stack">
        <Message severity="warn" :closable="false">{{ t('auth.recoveryHint') }}</Message>
        <div class="recovery-code-grid" role="list"><code v-for="code in recoveryCodes" :key="code" role="listitem">{{ code }}</code></div>
        <label class="switch-field" for="security-recovery-saved"><Checkbox id="security-recovery-saved" v-model="recoveryAcknowledged" binary /><span>{{ t('auth.recoverySaved') }}</span></label>
      </div>
      <template #footer><Button :label="t('auth.continue')" :disabled="!recoveryAcknowledged" @click="closeRecovery" /></template>
    </Dialog>

    <Dialog v-model:visible="passwordVisible" modal :header="t('security.changePassword')" :style="{ width: 'min(560px, 94vw)' }">
      <Fluid>
        <form id="change-password-form" class="form-stack" @submit.prevent="passwordMutation.mutate()">
          <div class="field"><label for="current-password">{{ t('security.currentPassword') }}</label><Password id="current-password" v-model="passwordForm.currentPassword" :feedback="false" toggle-mask autocomplete="current-password" required /></div>
          <div class="field"><label for="new-password">{{ t('auth.newPassword') }}</label><Password id="new-password" v-model="passwordForm.newPassword" toggle-mask autocomplete="new-password" required /></div>
          <div class="field"><label for="confirm-password">{{ t('security.confirmPassword') }}</label><Password id="confirm-password" v-model="passwordForm.confirmPassword" :feedback="false" toggle-mask autocomplete="new-password" required /></div>
          <div v-if="totpPolicyEnabled && securityQuery.data.value?.mfaEnabled" class="field"><label for="password-mfa">{{ t('auth.mfaValue') }}</label><Password id="password-mfa" v-model="passwordForm.mfaValue" :feedback="false" toggle-mask autocomplete="one-time-code" /></div>
          <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
        </form>
      </Fluid>
      <template #footer>
        <Button :label="t('common.cancel')" severity="secondary" text @click="passwordVisible = false" />
        <Button type="submit" form="change-password-form" icon="pi pi-save" :label="t('common.save')" :loading="passwordMutation.isPending.value" />
      </template>
    </Dialog>

    <ReauthenticateDialog v-model:visible="reauthVisible" @success="retryAfterElevation" />
  </div>
</template>
