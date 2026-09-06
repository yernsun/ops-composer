<script setup lang="ts">
import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import { useMutation, useQuery } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Message from 'primevue/message'
import Tag from 'primevue/tag'
import Toast from 'primevue/toast'
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'

import {
  ApiRequestError,
  api,
  type WebShellSessionDto,
  webShellSocket,
} from '@/shared/api/client'

const props = defineProps<{ hostId: string }>()
const { t, te } = useI18n()
const router = useRouter()
const terminalElement = ref<HTMLElement | null>(null)
const connectionState = ref<'idle' | 'creating' | 'connecting' | 'ready' | 'closed' | 'error'>('idle')
const errorCode = ref<string | null>(null)
const errorMessage = ref<string | null>(null)
const closeReason = ref<string | null>(null)
const webShellSession = ref<WebShellSessionDto | null>(null)
let terminal: Terminal | null = null
let fitAddon: FitAddon | null = null
let socket: WebSocket | null = null
let resizeObserver: ResizeObserver | null = null
let inputSubscription: { dispose: () => void } | null = null
let resizeSubscription: { dispose: () => void } | null = null
let intentionallyClosing = false

const hostQuery = useQuery({
  queryKey: ['hosts', props.hostId],
  queryFn: () => api.host(props.hostId),
  retry: false,
})

const stateSeverity = computed(() => {
  if (connectionState.value === 'ready') return 'success'
  if (connectionState.value === 'error') return 'danger'
  if (connectionState.value === 'closed') return 'secondary'
  return 'info'
})

const canConnect = computed(
  () => !['creating', 'connecting', 'ready'].includes(connectionState.value),
)

const localizedError = computed(() => {
  if (!errorCode.value) return ''
  const key = `webShell.errors.${errorCode.value}`
  return te(key) ? t(key) : (errorMessage.value ?? t('webShell.errors.web_shell_unavailable'))
})

const localizedCloseReason = computed(() => {
  if (!closeReason.value) return ''
  const key = `webShell.reasons.${closeReason.value}`
  return te(key) ? t(key) : closeReason.value
})

const createMutation = useMutation({
  mutationFn: () => api.createWebShellSession(props.hostId),
})

function initializeTerminal(): void {
  if (terminal || !terminalElement.value) return
  terminal = new Terminal({
    cursorBlink: true,
    cursorStyle: 'block',
    fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
    fontSize: 14,
    scrollback: 10_000,
    theme: {
      background: '#07111f',
      foreground: '#dce7f5',
      cursor: '#78a9ff',
      selectionBackground: '#294b7566',
    },
  })
  fitAddon = new FitAddon()
  terminal.loadAddon(fitAddon)
  terminal.open(terminalElement.value)
  inputSubscription = terminal.onData((value) => {
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(new TextEncoder().encode(value))
    }
  })
  resizeSubscription = terminal.onResize(({ cols, rows }) => {
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'resize', columns: cols, rows }))
    }
  })
  resizeObserver = new ResizeObserver(() => fitTerminal())
  resizeObserver.observe(terminalElement.value)
  fitTerminal()
}

function fitTerminal(): void {
  if (!terminal || !fitAddon) return
  try {
    fitAddon.fit()
  } catch {
    // Layout can transiently have zero dimensions while the tab is opening.
  }
}

function showApiError(error: unknown): void {
  connectionState.value = 'error'
  errorCode.value = error instanceof ApiRequestError ? error.code : 'web_shell_unavailable'
  errorMessage.value = error instanceof Error ? error.message : t('webShell.errors.web_shell_unavailable')
}

function processControlFrame(value: string): void {
  let message: Record<string, unknown>
  try {
    message = JSON.parse(value) as Record<string, unknown>
  } catch {
    showApiError(new Error(t('webShell.errors.web_shell_protocol_error')))
    return
  }
  if (message.type === 'ready') {
    connectionState.value = 'ready'
    fitTerminal()
    terminal?.focus()
    return
  }
  if (message.type === 'error') {
    connectionState.value = 'error'
    errorCode.value = typeof message.code === 'string' ? message.code : 'web_shell_unavailable'
    errorMessage.value = typeof message.message === 'string' ? message.message : null
    return
  }
  if (message.type === 'closed') {
    closeReason.value = typeof message.reason === 'string' ? message.reason : null
    if (connectionState.value !== 'error') connectionState.value = 'closed'
  }
}

async function connect(): Promise<void> {
  if (!canConnect.value) return
  intentionallyClosing = false
  errorCode.value = null
  errorMessage.value = null
  closeReason.value = null
  connectionState.value = 'creating'
  terminal?.reset()
  try {
    const created = await createMutation.mutateAsync()
    webShellSession.value = created
    connectionState.value = 'connecting'
    const nextSocket = webShellSocket(created.streamPath)
    socket = nextSocket
    nextSocket.binaryType = 'arraybuffer'
    nextSocket.addEventListener('message', (event) => {
      if (typeof event.data === 'string') {
        processControlFrame(event.data)
      } else if (event.data instanceof ArrayBuffer) {
        terminal?.write(new Uint8Array(event.data))
      }
    })
    nextSocket.addEventListener('error', () => {
      if (!intentionallyClosing && connectionState.value !== 'error') {
        showApiError(new Error(t('webShell.errors.web_shell_unavailable')))
      }
    })
    nextSocket.addEventListener('close', (event) => {
      socket = null
      webShellSession.value = null
      if (event.reason && event.code >= 4400) {
        errorCode.value = event.reason
        errorMessage.value = null
        connectionState.value = 'error'
        return
      }
      if (!intentionallyClosing && connectionState.value !== 'error') {
        connectionState.value = 'closed'
      }
    })
  } catch (error) {
    showApiError(error)
  }
}

async function disconnect(): Promise<void> {
  intentionallyClosing = true
  const sessionId = webShellSession.value?.webShellSessionId
  const currentSocket = socket
  if (currentSocket?.readyState === WebSocket.OPEN) {
    currentSocket.send(JSON.stringify({ type: 'close' }))
  }
  currentSocket?.close(1000)
  socket = null
  webShellSession.value = null
  if (sessionId) {
    try {
      await api.closeWebShellSession(sessionId)
    } catch {
      // Closing the WebSocket is authoritative; REST closure is best effort.
    }
  }
  connectionState.value = 'closed'
}

async function closeWindow(): Promise<void> {
  await disconnect()
  window.close()
  if (!window.closed) await router.replace({ name: 'hosts' })
}

function handleBeforeUnload(): void {
  intentionallyClosing = true
  socket?.close(1000)
}

onMounted(async () => {
  await nextTick()
  initializeTerminal()
  await connect()
  window.addEventListener('beforeunload', handleBeforeUnload)
})

onBeforeUnmount(() => {
  window.removeEventListener('beforeunload', handleBeforeUnload)
  handleBeforeUnload()
  resizeObserver?.disconnect()
  inputSubscription?.dispose()
  resizeSubscription?.dispose()
  terminal?.dispose()
})
</script>

<template>
  <main class="web-shell-page">
    <Toast position="top-right" />
    <header class="web-shell-header">
      <div class="web-shell-identity">
        <span class="brand-icon"><i class="pi pi-terminal" /></span>
        <div>
          <p>{{ t('webShell.title') }}</p>
          <h1>{{ hostQuery.data.value?.name ?? t('webShell.loadingHost') }}</h1>
          <span v-if="webShellSession">
            {{ webShellSession.username }}@{{ webShellSession.address }}:{{ webShellSession.sshPort }}
          </span>
          <span v-else-if="hostQuery.data.value">
            {{ hostQuery.data.value.address }}:{{ hostQuery.data.value.sshPort }}
          </span>
        </div>
      </div>
      <div class="web-shell-actions">
        <Tag :severity="stateSeverity" :value="t(`webShell.states.${connectionState}`)" />
        <Button
          icon="pi pi-refresh"
          :label="t('webShell.reconnect')"
          severity="secondary"
          outlined
          :disabled="!canConnect"
          @click="connect"
        />
        <Button
          icon="pi pi-times"
          :label="t('webShell.close')"
          severity="danger"
          outlined
          @click="closeWindow"
        />
      </div>
    </header>

    <Message
      v-if="errorCode === 'host_key_confirmation_required'"
      severity="warn"
      :closable="false"
      class="web-shell-message"
    >
      {{ t('webShell.errors.host_key_confirmation_required') }}
      <Button
        :label="t('webShell.returnToHosts')"
        icon="pi pi-arrow-left"
        text
        @click="router.push({ name: 'hosts' })"
      />
    </Message>
    <Message v-else-if="errorCode" severity="error" :closable="false" class="web-shell-message">
      {{ localizedError }}
    </Message>
    <Message v-else-if="closeReason" severity="secondary" :closable="false" class="web-shell-message">
      {{ t('webShell.closedReason', { reason: localizedCloseReason }) }}
    </Message>

    <section class="web-shell-terminal" :aria-label="t('webShell.terminalLabel')">
      <div ref="terminalElement" class="web-shell-terminal-mount" />
      <div v-if="connectionState === 'creating' || connectionState === 'connecting'" class="web-shell-overlay" aria-live="polite">
        <i class="pi pi-spin pi-spinner" />
        <span>{{ t(`webShell.states.${connectionState}`) }}</span>
      </div>
    </section>
    <footer class="web-shell-footer">
      <span><i class="pi pi-lock" /> {{ t('webShell.securityNotice') }}</span>
      <span v-if="webShellSession">
        {{ t('webShell.limits', {
          idle: Math.round(webShellSession.idleTimeoutSeconds / 60),
          maximum: Math.round(webShellSession.maxDurationSeconds / 3600),
        }) }}
      </span>
    </footer>
  </main>
</template>
