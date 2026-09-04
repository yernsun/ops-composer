import { config, flushPromises, shallowMount } from '@vue/test-utils'
import { createPinia } from 'pinia'
import type { Component } from 'vue'
import { defineComponent, h, nextTick, ref } from 'vue'
import { createI18n } from 'vue-i18n'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/app/App.vue'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import TargetPicker, { type TargetValue } from '@/components/TargetPicker.vue'
import AuthPanel from '@/features/auth/AuthPanel.vue'
import AppShell from '@/layout/AppShell.vue'
import CommandPage from '@/pages/CommandPage.vue'
import CredentialsPage from '@/pages/CredentialsPage.vue'
import DashboardPage from '@/pages/DashboardPage.vue'
import GroupsPage from '@/pages/GroupsPage.vue'
import HostsPage from '@/pages/HostsPage.vue'
import PlaybooksPage from '@/pages/PlaybooksPage.vue'
import RunDetailPage from '@/pages/RunDetailPage.vue'
import RunsPage from '@/pages/RunsPage.vue'
import SystemPage from '@/pages/SystemPage.vue'
import {
  ApiRequestError,
  api,
  type CredentialDto,
  type RunDto,
} from '@/shared/api/client'

const state = vi.hoisted(() => ({
  queries: {} as Record<string, unknown>,
  routePath: '/',
  pushes: vi.fn(),
  confirmations: vi.fn(),
  toasts: vi.fn(),
  mutationInput: { algorithm: 'ssh-ed25519', fingerprint: 'SHA256:test' },
}))

vi.mock('@tanstack/vue-query', async () => {
  const vue = await import('vue')
  const queryClient = {
    invalidateQueries: vi.fn(async () => undefined),
    removeQueries: vi.fn(),
    setQueryData: vi.fn(),
  }
  return {
    useQuery: (options: {
      queryKey: readonly unknown[]
      queryFn?: () => unknown
      refetchInterval?: number | ((query: { state: { data: unknown } }) => unknown)
    }) => {
      void Promise.resolve().then(() => options.queryFn?.()).catch(() => undefined)
      if (typeof options.refetchInterval === 'function') {
        options.refetchInterval({
          state: { data: state.queries[String(options.queryKey[0])] },
        })
      }
      return {
        data: vue.ref(state.queries[String(options.queryKey[0])]),
        isPending: vue.ref(false),
        isError: vue.ref(false),
        isFetching: vue.ref(false),
        isSuccess: vue.ref(true),
        refetch: vi.fn(async () => options.queryFn?.()),
      }
    },
    useMutation: (options: {
      mutationFn: (value?: unknown) => unknown
      onSuccess?: (result: unknown, variables: unknown) => unknown
      onError?: (error: Error, variables: unknown) => unknown
      onSettled?: () => unknown
    }) => {
      const mutate = vi.fn((value?: unknown) => {
        void Promise.resolve()
          .then(() => options.mutationFn(value))
          .then((result) => options.onSuccess?.(result, value))
          .catch((error: Error) => options.onError?.(error, value))
          .finally(() => options.onSettled?.())
      })
      mutate(state.mutationInput)
      return { isPending: vue.ref(false), mutate }
    },
    useQueryClient: () => queryClient,
  }
})

vi.mock('vue-router', async () => {
  const vue = await import('vue')
  const RouterLink = vue.defineComponent({
    name: 'RouterLink',
    setup: (_props, { slots }) => () => vue.h('a', slots.default?.()),
  })
  const RouterView = vue.defineComponent({ name: 'RouterView', render: () => vue.h('div') })
  return {
    RouterLink,
    RouterView,
    useRoute: () => ({ get path() { return state.routePath } }),
    useRouter: () => ({ push: state.pushes }),
  }
})

vi.mock('primevue/useconfirm', () => ({
  useConfirm: () => ({ require: state.confirmations }),
}))

vi.mock('primevue/usetoast', () => ({
  useToast: () => ({ add: state.toasts }),
}))

vi.mock('primevue/config', async (importOriginal) => {
  const actual = await importOriginal<typeof import('primevue/config')>()
  return {
    ...actual,
    usePrimeVue: () => ({ config: { locale: {} } }),
  }
})

const timestamp = '2026-09-04T00:00:00Z'
const hostId = '00000000-0000-4000-8000-000000000010'
const credentialId = '00000000-0000-4000-8000-000000000020'
const runId = '00000000-0000-4000-8000-000000000030'

const session = {
  userId: '00000000-0000-4000-8000-000000000001',
  username: 'admin',
  expiresAt: timestamp,
}
const host = {
  hostId,
  name: 'worker-01',
  address: '192.0.2.10',
  sshPort: 22,
  credentialId,
  pythonInterpreter: '/usr/bin/python3',
  enabled: true,
  description: 'worker',
  variables: { environment: 'test' },
  version: 1,
  createdAt: timestamp,
  updatedAt: timestamp,
}
const credential = {
  credentialId,
  name: 'production-password',
  credentialType: 'PASSWORD',
  username: 'root',
  publicConfig: { becomeEnabled: true },
  currentVersion: 2,
  enabled: true,
  description: 'credential',
  createdAt: timestamp,
  updatedAt: timestamp,
} satisfies CredentialDto
const group = {
  groupId: '00000000-0000-4000-8000-000000000040',
  name: 'workers',
  description: 'worker group',
  variables: { region: 'test' },
  hostIds: [hostId],
  createdAt: timestamp,
  updatedAt: timestamp,
}
const run = {
  runId,
  sourceRunId: null,
  kind: 'COMMAND',
  status: 'SUCCEEDED',
  targetSpec: { kind: 'HOSTS' },
  resolvedTargets: [{ hostId, name: host.name }],
  operationSpec: { mode: 'COMMAND' },
  inventorySnapshot: { all: { hosts: {} } },
  workspaceRevision: null,
  credentialVersions: { [credentialId]: 2 },
  timeoutSeconds: 60,
  forks: 1,
  claimedBy: 'worker-test',
  claimedAt: timestamp,
  startedAt: timestamp,
  finishedAt: timestamp,
  returnCode: 0,
  summary: { total: 1, succeeded: 1 },
  failureCode: null,
  failureMessage: null,
  requestedBy: session.userId,
  idempotencyKey: 'component-test-run',
  requestFingerprint: 'a'.repeat(64),
  createdAt: timestamp,
  updatedAt: timestamp,
} satisfies RunDto
const target = {
  runTargetId: '00000000-0000-4000-8000-000000000050',
  runId,
  hostId,
  hostName: host.name,
  hostAddress: host.address,
  status: 'SUCCEEDED',
  returnCode: 0,
  stdout: 'ok',
  stderr: '',
  result: {},
  outputTruncated: false,
  changedCount: 1,
  failedCount: 0,
  unreachableCount: 0,
  startedAt: timestamp,
  finishedAt: timestamp,
}
const event = {
  runEventId: '00000000-0000-4000-8000-000000000060',
  runId,
  runTargetId: target.runTargetId,
  sequence: 1,
  eventType: 'runner_on_ok',
  task: 'ping',
  stdout: 'ok',
  eventData: { host: host.name },
  createdAt: timestamp,
}

const slotData = {
  ...host,
  ...credential,
  ...group,
  ...run,
  ...target,
  status: 'SUCCEEDED',
}
const SlotStub = defineComponent({
  name: 'SlotStub',
  inheritAttrs: true,
  setup: (_props, { slots }) => () =>
    h(
      'div',
      Object.values(slots).flatMap((slot) =>
        slot?.({
          data: slotData,
          option: { value: 'system', label: 'System', icon: 'pi pi-cog' },
          value: 'system',
        }) ?? [],
      ),
    ),
})

function mountOptions() {
  const i18n = createI18n({
    legacy: false,
    locale: 'en-US',
    missingWarn: false,
    fallbackWarn: false,
    messages: { 'en-US': {} },
  })
  return {
    global: {
      plugins: [createPinia(), i18n],
      stubs: {
        teleport: true,
        transition: false,
        Button: SlotStub,
        Card: SlotStub,
        Column: SlotStub,
        DataTable: SlotStub,
        Dialog: SlotStub,
        PageHeader: SlotStub,
        Select: SlotStub,
        SelectButton: SlotStub,
        Tab: SlotStub,
        TabList: SlotStub,
        TabPanel: SlotStub,
        TabPanels: SlotStub,
        Tabs: SlotStub,
      },
    },
  }
}

class FakeEventSource {
  onerror: (() => void) | null = null
  close = vi.fn()
  addEventListener = vi.fn()
}

const NativeURL = URL
class BrowserTestURL extends NativeURL {
  static createObjectURL = vi.fn(() => 'blob:test-log')
  static revokeObjectURL = vi.fn()
}

beforeEach(() => {
  config.global.renderStubDefaultSlot = true
  state.routePath = '/'
  state.mutationInput = { algorithm: 'ssh-ed25519', fingerprint: 'SHA256:test' }
  state.queries = {
    auth: session,
    overview: {
      hostCount: 2,
      enabledHostCount: 1,
      runsToday: 3,
      failedRuns: 1,
      activeRuns: 0,
    },
    hosts: [host],
    credentials: [credential],
    groups: [group],
    runs: [run],
    playbooks: [
      {
        path: 'playbooks/site.yml',
        name: 'Site',
        size: 2048,
        modifiedAt: timestamp,
        sha256: 'b'.repeat(64),
      },
    ],
    run: { run, targets: [target] },
    'run-events': [event],
    'system-info': {
      name: 'OpsComposer',
      version: '0.1.0',
      database: 'PostgreSQL',
      queue: 'PostgreSQL SKIP LOCKED',
      projectForgeCommit: 'test',
      projectForgeTemplateDigest: 'test',
      playbookWorkspace: '/workspace',
    },
    'system-doctor': {
      database: { ok: true },
      playbookWorkspace: { ok: true, readOnlyExpected: true, path: '/workspace' },
      middlewareDependencies: [],
    },
  }
  vi.stubGlobal('EventSource', FakeEventSource)
  vi.stubGlobal('URL', BrowserTestURL)
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
  vi.spyOn(api, 'session').mockResolvedValue(session)
  vi.spyOn(api, 'login').mockResolvedValue(session)
  vi.spyOn(api, 'logout').mockResolvedValue(undefined)
  vi.spyOn(api, 'overview').mockResolvedValue(
    state.queries.overview as Awaited<ReturnType<typeof api.overview>>,
  )
  vi.spyOn(api, 'hosts').mockResolvedValue(
    state.queries.hosts as Awaited<ReturnType<typeof api.hosts>>,
  )
  vi.spyOn(api, 'credentials').mockResolvedValue(
    state.queries.credentials as Awaited<ReturnType<typeof api.credentials>>,
  )
  vi.spyOn(api, 'groups').mockResolvedValue(
    state.queries.groups as Awaited<ReturnType<typeof api.groups>>,
  )
  vi.spyOn(api, 'runs').mockResolvedValue(
    state.queries.runs as Awaited<ReturnType<typeof api.runs>>,
  )
  vi.spyOn(api, 'playbooks').mockResolvedValue(
    state.queries.playbooks as Awaited<ReturnType<typeof api.playbooks>>,
  )
  vi.spyOn(api, 'run').mockResolvedValue(
    state.queries.run as Awaited<ReturnType<typeof api.run>>,
  )
  vi.spyOn(api, 'runEvents').mockResolvedValue(
    state.queries['run-events'] as Awaited<ReturnType<typeof api.runEvents>>,
  )
  vi.spyOn(api, 'systemInfo').mockResolvedValue(
    state.queries['system-info'] as Awaited<ReturnType<typeof api.systemInfo>>,
  )
  vi.spyOn(api, 'systemDoctor').mockResolvedValue(
    state.queries['system-doctor'] as Awaited<ReturnType<typeof api.systemDoctor>>,
  )
  vi.spyOn(api, 'createHost').mockResolvedValue(host)
  vi.spyOn(api, 'updateHost').mockResolvedValue(host)
  vi.spyOn(api, 'deleteHost').mockResolvedValue(undefined)
  vi.spyOn(api, 'testHost').mockResolvedValue(run)
  vi.spyOn(api, 'scanHostKeys').mockResolvedValue([
    { algorithm: 'ssh-ed25519', publicKey: 'AAAA', fingerprint: 'SHA256:test' },
  ])
  vi.spyOn(api, 'confirmHostKey').mockResolvedValue({
    hostId,
    algorithm: 'ssh-ed25519',
    publicKey: 'AAAA',
    fingerprint: 'SHA256:test',
    trustedBy: session.userId,
    trustedAt: timestamp,
  })
  vi.spyOn(api, 'createGroup').mockResolvedValue(group)
  vi.spyOn(api, 'updateGroup').mockResolvedValue(group)
  vi.spyOn(api, 'deleteGroup').mockResolvedValue(undefined)
  vi.spyOn(api, 'createCredential').mockResolvedValue(credential)
  vi.spyOn(api, 'rotateCredential').mockResolvedValue(credential)
  vi.spyOn(api, 'deleteCredential').mockResolvedValue(undefined)
  vi.spyOn(api, 'createCommandRun').mockResolvedValue(run)
  vi.spyOn(api, 'createPlaybookRun').mockResolvedValue(run)
  vi.spyOn(api, 'cancelRun').mockResolvedValue(run)
  vi.spyOn(api, 'retryRun').mockResolvedValue(run)
  vi.spyOn(api, 'validatePlaybook').mockResolvedValue({ valid: true, output: 'ok' })
})

describe('PrimeVue application views', () => {
  it('renders all Overview metrics from the camelCase API response', async () => {
    const wrapper = shallowMount(DashboardPage, mountOptions())
    await flushPromises()

    expect(wrapper.findAll('.stat-card strong').map((item) => item.text())).toEqual([
      '2',
      '0',
      '3',
      '1',
    ])
    expect(wrapper.find('.status-donut strong').text()).toBe('2')
    wrapper.unmount()
  })

  it('renders every M1 page with populated query states', async () => {
    const pages: Array<{ component: Component; props?: Record<string, unknown> }> = [
      { component: DashboardPage },
      { component: HostsPage },
      { component: GroupsPage },
      { component: CredentialsPage },
      { component: CommandPage },
      { component: PlaybooksPage },
      { component: RunsPage },
      { component: RunDetailPage, props: { id: runId } },
      { component: SystemPage },
    ]

    for (const page of pages) {
      const wrapper = shallowMount(page.component, {
        ...mountOptions(),
        ...(page.props ? { props: page.props } : {}),
      })
      await flushPromises()
      expect(wrapper.find('.page-stack').exists()).toBe(true)
      for (const form of wrapper.findAll('form')) {
        await form.trigger('submit').catch(() => undefined)
      }
      for (const control of wrapper.findAllComponents(SlotStub)) {
        await control.trigger('click').catch(() => undefined)
      }
      await flushPromises()
      wrapper.unmount()
    }
  })

  it('renders shared components, authentication states, and the shell', async () => {
    const header = shallowMount(PageHeader, {
      ...mountOptions(),
      props: { title: 'Hosts', description: 'Inventory' },
      slots: { default: () => h('button', 'Refresh') },
    })
    expect(header.text()).toContain('Hosts')
    expect(header.text()).toContain('Refresh')

    for (const status of ['SUCCEEDED', 'PARTIAL', 'FAILED', 'RUNNING', 'UNKNOWN']) {
      const tag = shallowMount(StatusTag, { ...mountOptions(), props: { status } })
      expect(tag.exists()).toBe(true)
      tag.unmount()
    }

    const pickerValue = ref<TargetValue>({ kind: 'HOSTS', hostIds: [hostId], groupId: null })
    const picker = shallowMount(TargetPicker, {
      ...mountOptions(),
      props: {
        modelValue: pickerValue.value,
        'onUpdate:modelValue': (value: TargetValue) => { pickerValue.value = value },
      },
    })
    expect(picker.find('.target-picker').exists()).toBe(true)

    const panel = shallowMount(AuthPanel, mountOptions())
    expect(panel.find('.login-page').exists()).toBe(true)

    const shell = shallowMount(AppShell, {
      ...mountOptions(),
      props: { session },
    })
    expect(shell.text()).toContain('OpsComposer')
    shell.unmount()

    const application = shallowMount(App, mountOptions())
    await nextTick()
    expect(application.exists()).toBe(true)
    application.unmount()
  })

  it('starts a host-key scan when a connection test needs explicit trust', async () => {
    state.mutationInput = hostId as unknown as typeof state.mutationInput
    vi.mocked(api.testHost).mockRejectedValue(
      new ApiRequestError(
        409,
        'host_key_confirmation_required',
        'SSH host key confirmation is required',
        { hosts: [{ hostId, name: host.name }] },
        'request-test',
        null,
      ),
    )

    const wrapper = shallowMount(HostsPage, mountOptions())
    await flushPromises()

    expect(api.scanHostKeys).toHaveBeenCalledWith(hostId)
    expect(state.toasts).toHaveBeenCalledWith(
      expect.objectContaining({
        severity: 'warn',
        detail: 'hosts.confirmationRequired',
      }),
    )
    wrapper.unmount()
  })

  it('explains legacy preparation failures caused by an unconfirmed host key', async () => {
    const rejectedRun = {
      ...run,
      status: 'REJECTED',
      failureCode: 'PREPARATION_FAILED',
      failureMessage: 'run preparation failed',
    } satisfies RunDto
    state.queries.run = { run: rejectedRun, targets: [target] }
    state.queries['run-events'] = [
      {
        ...event,
        eventType: 'run_rejected',
        eventData: {
          code: 'PREPARATION_FAILED',
          message: `host ${host.name} has no confirmed SSH host key`,
        },
      },
    ]

    const wrapper = shallowMount(RunDetailPage, {
      ...mountOptions(),
      props: { id: runId },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('HOST_KEY_CONFIRMATION_REQUIRED')
    expect(wrapper.text()).toContain('hosts.confirmationRequiredRun')
    wrapper.unmount()
  })
})
