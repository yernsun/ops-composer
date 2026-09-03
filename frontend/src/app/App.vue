<script setup lang="ts">
import Button from 'primevue/button'
import Message from 'primevue/message'
import ProgressSpinner from 'primevue/progressspinner'
import { useI18n } from 'vue-i18n'

import AuthPanel from '@/features/auth/AuthPanel.vue'
import { useSessionState } from '@/features/auth/session'
import AppShell from '@/layout/AppShell.vue'

const { t } = useI18n()
const { sessionQuery, session, state: authState } = useSessionState()
</script>

<template>
  <section v-if="sessionQuery.isError.value" class="center-state" role="alert">
    <Message severity="error" :closable="false">{{ t('auth.errors.session_failed') }}</Message>
    <Button icon="pi pi-refresh" :label="t('common.retry')" @click="sessionQuery.refetch()" />
  </section>
  <section v-else-if="authState === 'loading'" class="center-state" aria-live="polite">
    <ProgressSpinner class="auth-spinner" stroke-width="5" />
    <p>{{ t('auth.restoringSession') }}</p>
  </section>
  <AuthPanel v-else-if="authState === 'guest'" />
  <AppShell v-else-if="session" :session="session" />
</template>
