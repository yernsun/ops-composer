import { flushPromises, shallowMount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { createI18n } from 'vue-i18n'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import WebShellPage from '@/pages/WebShellPage.vue'
import { api } from '@/shared/api/client'
import enUS from '@/shared/i18n/locales/en-US.json'

const testState = vi.hoisted(() => ({
  terminalData: null as ((value: string) => void) | null,
  terminalResize: null as ((value: { cols: number; rows: number }) => void) | null,
  terminalWrites: [] as Uint8Array[],
  focused: 0,
  sockets: [] as FakeSocket[],
}))

vi.mock('@tanstack/vue-query', async () => {
  const vue = await import('vue')
  return {
    useQuery: (options: { queryFn: () => unknown }) => {
      void options.queryFn()
      return {
        data: vue.ref({
          hostId: '00000000-0000-4000-8000-000000000010',
          name: 'worker-01',
          address: '192.0.2.10',
          sshPort: 22,
          enabled: true,
        }),
        isPending: vue.ref(false),
      }
    },
    useMutation: (options: { mutationFn: () => unknown }) => ({
      mutateAsync: vi.fn(() => options.mutationFn()),
      isPending: vue.ref(false),
    }),
  }
})

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}))

vi.mock('@xterm/xterm', () => ({
  Terminal: class {
    loadAddon(): void {}
    open(): void {}
    reset(): void {}
    dispose(): void {}
    focus(): void {
      testState.focused += 1
    }
    write(value: Uint8Array): void {
      testState.terminalWrites.push(value)
    }
    onData(callback: (value: string) => void): { dispose: () => void } {
      testState.terminalData = callback
      return { dispose: vi.fn() }
    }
    onResize(
      callback: (value: { cols: number; rows: number }) => void,
    ): { dispose: () => void } {
      testState.terminalResize = callback
      return { dispose: vi.fn() }
    }
  },
}))

vi.mock('@xterm/addon-fit', () => ({
  FitAddon: class {
    fit(): void {}
  },
}))

class FakeSocket {
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSING = 2
  static readonly CLOSED = 3

  readonly send = vi.fn()
  readonly close = vi.fn((code = 1000) => {
    this.readyState = FakeSocket.CLOSED
    this.emit('close', { code, reason: '' })
  })
  binaryType = 'blob'
  readyState = FakeSocket.OPEN
  private readonly listeners = new Map<string, Array<(event: never) => void>>()

  constructor(readonly url: string) {
    testState.sockets.push(this)
  }

  addEventListener(name: string, callback: (event: never) => void): void {
    const callbacks = this.listeners.get(name) ?? []
    callbacks.push(callback)
    this.listeners.set(name, callbacks)
  }

  emit(name: string, event: unknown): void {
    for (const callback of this.listeners.get(name) ?? []) callback(event as never)
  }
}

const SlotStub = defineComponent({
  inheritAttrs: true,
  setup: (_props, { slots, attrs }) => () =>
    h('div', attrs, [String(attrs.value ?? ''), ...(slots.default?.() ?? [])]),
})

describe('dedicated Web Shell page', () => {
  beforeEach(() => {
    testState.terminalData = null
    testState.terminalResize = null
    testState.terminalWrites = []
    testState.focused = 0
    testState.sockets = []
    vi.stubGlobal('WebSocket', FakeSocket)
    vi.stubGlobal(
      'ResizeObserver',
      class {
        observe(): void {}
        disconnect(): void {}
      },
    )
    vi.spyOn(api, 'host').mockResolvedValue({} as Awaited<ReturnType<typeof api.host>>)
    vi.spyOn(api, 'createWebShellSession').mockResolvedValue({
      webShellSessionId: '00000000-0000-4000-8000-000000000099',
      hostId: '00000000-0000-4000-8000-000000000010',
      hostName: 'worker-01',
      address: '192.0.2.10',
      sshPort: 22,
      username: 'deploy',
      streamPath: '/api/v1/web-shell-sessions/00000000-0000-4000-8000-000000000099/stream',
      ticketExpiresAt: '2026-09-06T00:00:30Z',
      idleTimeoutSeconds: 1800,
      maxDurationSeconds: 28800,
    })
    vi.spyOn(api, 'closeWebShellSession').mockResolvedValue(undefined)
  })

  it('streams terminal bytes, resize control, and closes the server session', async () => {
    const i18n = createI18n({
      legacy: false,
      locale: 'en-US',
      messages: { 'en-US': enUS },
    })
    const wrapper = shallowMount(WebShellPage, {
      props: { hostId: '00000000-0000-4000-8000-000000000010' },
      global: {
        plugins: [i18n],
        stubs: { Button: SlotStub, Message: SlotStub, Tag: SlotStub, Toast: SlotStub },
      },
    })
    await flushPromises()

    expect(api.createWebShellSession).toHaveBeenCalledOnce()
    const socket = testState.sockets[0]
    expect(socket?.url).toContain('/api/v1/web-shell-sessions/')
    expect(socket?.binaryType).toBe('arraybuffer')

    socket?.emit('message', { data: JSON.stringify({ type: 'ready' }) })
    testState.terminalData?.('ls\r')
    testState.terminalResize?.({ cols: 132, rows: 43 })
    socket?.emit('message', { data: new Uint8Array([111, 107]).buffer })

    expect(testState.focused).toBe(1)
    expect(socket?.send).toHaveBeenCalledWith(new TextEncoder().encode('ls\r'))
    expect(socket?.send).toHaveBeenCalledWith(
      JSON.stringify({ type: 'resize', columns: 132, rows: 43 }),
    )
    expect(testState.terminalWrites[0]).toEqual(new Uint8Array([111, 107]))

    const view = wrapper.vm as unknown as { disconnect: () => Promise<void> }
    await view.disconnect()
    expect(api.closeWebShellSession).toHaveBeenCalledWith(
      '00000000-0000-4000-8000-000000000099',
    )
    expect(socket?.close).toHaveBeenCalled()
    wrapper.unmount()
  })

  it('surfaces a stable pre-upgrade ticket or host-lock rejection', async () => {
    const i18n = createI18n({
      legacy: false,
      locale: 'en-US',
      messages: { 'en-US': enUS },
    })
    const wrapper = shallowMount(WebShellPage, {
      props: { hostId: '00000000-0000-4000-8000-000000000010' },
      global: {
        plugins: [i18n],
        stubs: { Button: SlotStub, Message: SlotStub, Tag: SlotStub, Toast: SlotStub },
      },
    })
    await flushPromises()
    testState.sockets[0]?.emit('close', { code: 4408, reason: 'host_busy' })
    await flushPromises()

    expect(wrapper.text()).toContain('This host is busy')
    wrapper.unmount()
  })
})
