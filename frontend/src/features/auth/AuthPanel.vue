<script setup lang="ts">
import { useMutation, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Checkbox from 'primevue/checkbox'
import Fluid from 'primevue/fluid'
import IconField from 'primevue/iconfield'
import InputIcon from 'primevue/inputicon'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Password from 'primevue/password'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import {
  api,
  ApiRequestError,
  type AuthChallengeDto,
  type AuthResultDto,
  type SessionDto,
} from '@/shared/api/client'

import { applySessionTransition, authErrorTranslationKey } from './session'

type PanelMode = 'login' | 'activate' | 'challenge' | 'recovery'

const { t } = useI18n()
const queryClient = useQueryClient()
const mode = ref<PanelMode>('login')
const username = ref('admin')
const password = ref('')
const activationCode = ref('')
const activationPassword = ref('')
const mfaValue = ref('')
const challenge = ref<AuthChallengeDto | null>(null)
const recoveryCodes = ref<string[]>([])
const recoveryAcknowledged = ref(false)
const pendingSession = ref<SessionDto | null>(null)
const error = ref<unknown>(null)

function isChallenge(result: AuthResultDto): result is AuthChallengeDto {
  return 'nextStep' in result
}

async function handleAuthResult(result: AuthResultDto): Promise<void> {
  error.value = null
  password.value = ''
  activationPassword.value = ''
  if (isChallenge(result)) {
    challenge.value = result
    mfaValue.value = ''
    mode.value = 'challenge'
    return
  }
  await applySessionTransition(queryClient, result)
}

const loginMutation = useMutation({
  mutationFn: api.login,
  onSuccess: handleAuthResult,
  onError: (value) => {
    error.value = value
  },
})

const activationMutation = useMutation({
  mutationFn: api.activate,
  onSuccess: handleAuthResult,
  onError: (value) => {
    error.value = value
  },
})

const mfaMutation = useMutation({
  mutationFn: async () => {
    if (!challenge.value) throw new Error(t('auth.errors.invalid_auth_challenge'))
    return challenge.value.nextStep === 'MFA_ENROLLMENT'
      ? api.confirmMfaEnrollment(mfaValue.value)
      : api.verifyMfa(mfaValue.value)
  },
  onSuccess: async (result) => {
    error.value = null
    mfaValue.value = ''
    const codes = result.recoveryCodes ?? []
    if (codes.length) {
      recoveryCodes.value = codes
      pendingSession.value = result.session
      recoveryAcknowledged.value = false
      mode.value = 'recovery'
      return
    }
    await applySessionTransition(queryClient, result.session)
  },
  onError: (value) => {
    error.value = value
  },
})

const errorMessage = computed(() => {
  const key = authErrorTranslationKey(error.value)
  if (key) {
    const seconds = error.value instanceof ApiRequestError ? error.value.retryAfter ?? 0 : 0
    return t(key, { seconds })
  }
  return error.value ? t('auth.errors.unavailable') : ''
})

const pending = computed(
  () =>
    loginMutation.isPending.value ||
    activationMutation.isPending.value ||
    mfaMutation.isPending.value,
)

function submitLogin(): void {
  if (!username.value.trim() || !password.value) return
  loginMutation.mutate({ username: username.value.trim(), password: password.value })
}

function submitActivation(): void {
  if (!activationCode.value || !activationPassword.value) return
  activationMutation.mutate({
    activationCode: activationCode.value.trim(),
    password: activationPassword.value,
  })
}

function submitMfa(): void {
  if (mfaValue.value.trim().length < 6) return
  mfaMutation.mutate()
}

function reset(next: PanelMode): void {
  error.value = null
  challenge.value = null
  mfaValue.value = ''
  mode.value = next
}

async function continueAfterRecovery(): Promise<void> {
  if (!pendingSession.value || !recoveryAcknowledged.value) return
  recoveryCodes.value = []
  const session = pendingSession.value
  pendingSession.value = null
  await applySessionTransition(queryClient, session)
}
</script>

<template>
  <main class="login-page">
    <section class="login-brand" aria-labelledby="brand-title">
      <div class="brand-mark" aria-hidden="true"><i class="pi pi-sparkles" /></div>
      <p class="eyebrow">OpsComposer</p>
      <h1 id="brand-title">{{ t('app.productName') }}</h1>
      <p>{{ t('app.productTagline') }}</p>
      <ul class="login-features" :aria-label="t('login.capabilities')">
        <li><i class="pi pi-server" />{{ t('login.features.inventory') }}</li>
        <li><i class="pi pi-key" />{{ t('login.features.credentials') }}</li>
        <li><i class="pi pi-bolt" />{{ t('login.features.execution') }}</li>
      </ul>
    </section>

    <section class="login-card" aria-labelledby="login-title">
      <template v-if="mode === 'login'">
        <div>
          <p class="eyebrow">{{ t('auth.eyebrow') }}</p>
          <h2 id="login-title">{{ t('auth.loginTitle') }}</h2>
          <p class="muted">{{ t('auth.multiAdminHint') }}</p>
        </div>
        <Fluid>
          <form class="form-stack" @submit.prevent="submitLogin">
            <label for="username">{{ t('auth.username') }}</label>
            <IconField>
              <InputIcon class="pi pi-user" />
              <InputText id="username" v-model="username" autocomplete="username" autofocus required maxlength="64" />
            </IconField>
            <label for="password">{{ t('auth.password') }}</label>
            <Password id="password" v-model="password" :feedback="false" toggle-mask autocomplete="current-password" required />
            <Message v-if="errorMessage" severity="error" :closable="false" role="alert">{{ errorMessage }}</Message>
            <Button type="submit" icon="pi pi-sign-in" :label="t('auth.login')" :loading="pending" />
            <Button type="button" severity="secondary" text :label="t('auth.activateAccount')" @click="reset('activate')" />
          </form>
        </Fluid>
        <p class="bootstrap-hint"><i class="pi pi-shield" aria-hidden="true" />{{ t('auth.bootstrapHint') }}</p>
      </template>

      <template v-else-if="mode === 'activate'">
        <div>
          <p class="eyebrow">{{ t('auth.activationEyebrow') }}</p>
          <h2 id="login-title">{{ t('auth.activationTitle') }}</h2>
          <p class="muted">{{ t('auth.activationHint') }}</p>
        </div>
        <Fluid>
          <form class="form-stack" @submit.prevent="submitActivation">
            <label for="activation-code">{{ t('auth.activationCode') }}</label>
            <Password id="activation-code" v-model="activationCode" :feedback="false" toggle-mask autocomplete="one-time-code" required />
            <label for="activation-password">{{ t('auth.newPassword') }}</label>
            <Password id="activation-password" v-model="activationPassword" toggle-mask autocomplete="new-password" required />
            <Message v-if="errorMessage" severity="error" :closable="false" role="alert">{{ errorMessage }}</Message>
            <Button type="submit" icon="pi pi-user-plus" :label="t('auth.activate')" :loading="pending" />
            <Button type="button" severity="secondary" text :label="t('auth.backToLogin')" @click="reset('login')" />
          </form>
        </Fluid>
      </template>

      <template v-else-if="mode === 'challenge' && challenge">
        <div>
          <p class="eyebrow">{{ t('auth.mfaEyebrow') }}</p>
          <h2 id="login-title">{{ challenge.nextStep === 'MFA_ENROLLMENT' ? t('auth.enrollTitle') : t('auth.verifyTitle') }}</h2>
          <p class="muted">{{ challenge.nextStep === 'MFA_ENROLLMENT' ? t('auth.enrollHint') : t('auth.verifyHint') }}</p>
        </div>
        <div v-if="challenge.enrollmentSecret" class="one-time-secret" aria-live="polite">
          <span>{{ t('auth.totpSecret') }}</span>
          <code>{{ challenge.enrollmentSecret }}</code>
          <small>{{ t('auth.totpSecretHint') }}</small>
        </div>
        <Fluid>
          <form class="form-stack" @submit.prevent="submitMfa">
            <label for="mfa-value">{{ t('auth.mfaValue') }}</label>
            <Password id="mfa-value" v-model="mfaValue" :feedback="false" toggle-mask autocomplete="one-time-code" required maxlength="64" autofocus />
            <Message v-if="errorMessage" severity="error" :closable="false" role="alert">{{ errorMessage }}</Message>
            <Button type="submit" icon="pi pi-shield" :label="t('auth.verify')" :loading="pending" />
            <Button type="button" severity="secondary" text :label="t('auth.backToLogin')" @click="reset('login')" />
          </form>
        </Fluid>
      </template>

      <template v-else-if="mode === 'recovery'">
        <div>
          <p class="eyebrow">{{ t('auth.recoveryEyebrow') }}</p>
          <h2 id="login-title">{{ t('auth.recoveryTitle') }}</h2>
          <p class="muted">{{ t('auth.recoveryHint') }}</p>
        </div>
        <div class="recovery-code-grid" role="list">
          <code v-for="code in recoveryCodes" :key="code" role="listitem">{{ code }}</code>
        </div>
        <label class="switch-field" for="recovery-saved">
          <Checkbox id="recovery-saved" v-model="recoveryAcknowledged" binary />
          <span>{{ t('auth.recoverySaved') }}</span>
        </label>
        <Button :disabled="!recoveryAcknowledged" :label="t('auth.continue')" icon="pi pi-arrow-right" @click="continueAfterRecovery" />
      </template>
    </section>
  </main>
</template>
