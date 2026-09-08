<script setup lang="ts">
import { useMutation, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import Fluid from 'primevue/fluid'
import Message from 'primevue/message'
import Password from 'primevue/password'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

import { api, ApiRequestError } from '@/shared/api/client'

import { applySessionTransition } from './session'
import { useAuthorization } from './authorization'

const props = defineProps<{
  visible: boolean
  reason?: string
}>()
const emit = defineEmits<{
  'update:visible': [value: boolean]
  success: []
}>()

const { t } = useI18n()
const queryClient = useQueryClient()
const { totpPolicyEnabled } = useAuthorization()
const password = ref('')
const mfaValue = ref('')
const error = ref('')

watch(
  () => props.visible,
  (visible) => {
    if (!visible) return
    password.value = ''
    mfaValue.value = ''
    error.value = ''
  },
)

const mutation = useMutation({
  mutationFn: () => api.reauthenticate({
    password: password.value,
    mfaValue: totpPolicyEnabled.value ? mfaValue.value : null,
  }),
  onSuccess: async (session) => {
    password.value = ''
    mfaValue.value = ''
    await applySessionTransition(queryClient, session)
    emit('update:visible', false)
    emit('success')
  },
  onError: (value) => {
    error.value = value instanceof ApiRequestError
      ? t(`auth.errors.${value.code}`, value.message)
      : t('auth.errors.unavailable')
  },
})

const canSubmit = computed(
  () => password.value.length > 0 && (
    !totpPolicyEnabled.value || mfaValue.value.trim().length >= 6
  ),
)
const effectiveReason = computed(() => {
  if (!totpPolicyEnabled.value) return t('auth.passwordReauthenticationHint')
  return props.reason || t('auth.reauthenticationHint')
})
</script>

<template>
  <Dialog
    :visible="visible"
    modal
    :header="t('auth.reauthenticationTitle')"
    :style="{ width: 'min(520px, 94vw)' }"
    @update:visible="emit('update:visible', $event)"
  >
    <Fluid>
      <form id="reauthentication-form" class="form-stack" @submit.prevent="mutation.mutate()">
        <Message severity="warn" :closable="false">
          {{ effectiveReason }}
        </Message>
        <div class="field">
          <label for="reauth-password">{{ t('auth.password') }}</label>
          <Password
            id="reauth-password"
            v-model="password"
            :feedback="false"
            toggle-mask
            autocomplete="current-password"
            required
            autofocus
          />
        </div>
        <div v-if="totpPolicyEnabled" class="field">
          <label for="reauth-mfa">{{ t('auth.mfaValue') }}</label>
          <Password
            id="reauth-mfa"
            v-model="mfaValue"
            :feedback="false"
            toggle-mask
            autocomplete="one-time-code"
            maxlength="64"
            required
          />
        </div>
        <Message v-if="error" severity="error" :closable="false" role="alert">{{ error }}</Message>
      </form>
    </Fluid>
    <template #footer>
      <Button :label="t('common.cancel')" severity="secondary" text @click="emit('update:visible', false)" />
      <Button
        type="submit"
        form="reauthentication-form"
        icon="pi pi-shield"
        :label="t('auth.reauthenticate')"
        :loading="mutation.isPending.value"
        :disabled="!canSubmit"
      />
    </template>
  </Dialog>
</template>
