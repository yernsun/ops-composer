<script setup lang="ts">
import { useMutation, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Fluid from 'primevue/fluid'
import IconField from 'primevue/iconfield'
import InputIcon from 'primevue/inputicon'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Password from 'primevue/password'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { api, ApiRequestError } from '@/shared/api/client'

import { applySessionTransition, authErrorTranslationKey } from './session'

const { t } = useI18n()
const queryClient = useQueryClient()
const username = ref('admin')
const password = ref('')
const error = ref<unknown>(null)

const loginMutation = useMutation({
  mutationFn: api.login,
  onSuccess: async (session) => {
    error.value = null
    password.value = ''
    await applySessionTransition(queryClient, session)
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

function submit(): void {
  if (!username.value.trim() || !password.value) return
  loginMutation.mutate({ username: username.value.trim(), password: password.value })
}
</script>

<template>
  <main class="login-page">
    <section class="login-brand" aria-labelledby="brand-title">
      <div class="brand-mark" aria-hidden="true">
        <i class="pi pi-sparkles" />
      </div>
      <p class="eyebrow">OpsComposer</p>
      <h1 id="brand-title">{{ t('app.productName') }}</h1>
      <p>{{ t('app.productTagline') }}</p>
      <ul class="login-features" aria-label="Product capabilities">
        <li><i class="pi pi-server" />{{ t('login.features.inventory') }}</li>
        <li><i class="pi pi-key" />{{ t('login.features.credentials') }}</li>
        <li><i class="pi pi-bolt" />{{ t('login.features.execution') }}</li>
      </ul>
    </section>

    <section class="login-card" aria-labelledby="login-title">
      <div>
        <p class="eyebrow">{{ t('auth.eyebrow') }}</p>
        <h2 id="login-title">{{ t('auth.loginTitle') }}</h2>
        <p class="muted">{{ t('auth.singleAdminHint') }}</p>
      </div>
      <Fluid>
        <form class="form-stack" @submit.prevent="submit">
          <label for="username">{{ t('auth.username') }}</label>
          <IconField>
            <InputIcon class="pi pi-user" />
            <InputText
              id="username"
              v-model="username"
              autocomplete="username"
              autofocus
              required
              maxlength="64"
            />
          </IconField>

          <label for="password">{{ t('auth.password') }}</label>
          <Password
            id="password"
            v-model="password"
            :feedback="false"
            toggle-mask
            autocomplete="current-password"
            required
            @keydown.enter="submit"
          />

          <Message v-if="errorMessage" severity="error" :closable="false" role="alert">
            {{ errorMessage }}
          </Message>
          <Button
            type="submit"
            icon="pi pi-sign-in"
            :label="t('auth.login')"
            :loading="loginMutation.isPending.value"
          />
        </form>
      </Fluid>
      <p class="bootstrap-hint">
        <i class="pi pi-shield" aria-hidden="true" />
        {{ t('auth.bootstrapHint') }}
      </p>
    </section>
  </main>
</template>
