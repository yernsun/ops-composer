import type { components } from './schema'

export const AUTH_UNAUTHORIZED_EVENT = 'ops-composer:auth-unauthorized'

export type SessionDto = components['schemas']['SessionResponse']
export type LoginDto = components['schemas']['LoginRequest']
export type CredentialDto = components['schemas']['Credential']
export type CredentialCreateDto = components['schemas']['CredentialCreateRequest']
export type CredentialRotateDto = components['schemas']['CredentialRotateRequest']
export type HostDto = components['schemas']['Host']
export type HostCreateDto = components['schemas']['HostCreateRequest']
export type HostUpdateDto = components['schemas']['HostUpdateRequest']
export type HostGroupDto = components['schemas']['HostGroup']
export type GroupDto = components['schemas']['GroupRequest']
export type HostKeyDto = components['schemas']['HostKey']
export type HostKeyScanDto = components['schemas']['HostKeyScanResponse']
export type RunDto = components['schemas']['Run']
export type RunTargetDto = components['schemas']['RunTarget']
export type RunEventDto = components['schemas']['RunEvent']
export type RunDetailDto = components['schemas']['RunDetailResponse']
export type CommandRunDto = components['schemas']['CommandRunRequest']
export type PlaybookRunDto = components['schemas']['PlaybookRunRequest']
export type PlaybookDto = components['schemas']['PlaybookSummaryResponse']
export type PlaybookConfigDto = components['schemas']['PlaybookConfigResponse']
export type DatabasePlaybookDto = components['schemas']['DatabasePlaybookDetailResponse']
export type DatabasePlaybookCreateDto = components['schemas']['DatabasePlaybookCreateRequest']
export type DatabasePlaybookUpdateDto = components['schemas']['DatabasePlaybookUpdateRequest']
export type PlaybookValidationDto = components['schemas']['PlaybookValidationRequest']
export type PlaybookValidationResultDto = components['schemas']['PlaybookValidationResponse']
export type OverviewDto = components['schemas']['OverviewResponse']
export type WebShellSessionDto = components['schemas']['WebShellSessionResponse']

export interface SystemInfoDto {
  name: string
  version: string
  database: string
  queue: string
  projectForgeCommit: string
  projectForgeTemplateDigest: string
  playbookWorkspace: string
  playbookSourceMode: string
  webShell: {
    enabled: boolean
    maxSessions: number
    idleTimeoutSeconds: number
    maxDurationSeconds: number
  }
}

interface ErrorEnvelope {
  code?: string
  message?: string
  details?: Record<string, unknown> | null
  requestId?: string | null
}

export class ApiRequestError extends Error {
  readonly status: number
  readonly code: string
  readonly details: Record<string, unknown> | null
  readonly requestId: string | null
  readonly retryAfter: number | null

  constructor(
    status: number,
    code: string,
    message: string,
    details: Record<string, unknown> | null,
    requestId: string | null,
    retryAfter: number | null,
  ) {
    super(message)
    this.name = 'ApiRequestError'
    this.status = status
    this.code = code
    this.details = details
    this.requestId = requestId
    this.retryAfter = retryAfter
  }
}

function cookie(name: string): string | null {
  const prefix = `${encodeURIComponent(name)}=`
  const entry = document.cookie
    .split(';')
    .map((value) => value.trim())
    .find((value) => value.startsWith(prefix))
  if (!entry) return null
  try {
    return decodeURIComponent(entry.slice(prefix.length))
  } catch {
    return null
  }
}

export function readCsrfToken(): string | null {
  return cookie('__Host-ops-composer-csrf') ?? cookie('ops-composer-csrf')
}

export function resolveApiBaseUrl(
  configured: string | undefined,
  browserOrigin: string = window.location.origin,
): string {
  const value = (configured ?? '').trim()
  if (!value) return browserOrigin
  const resolved = new URL(value, browserOrigin)
  if (resolved.origin !== browserOrigin) {
    throw new Error('VITE_API_BASE_URL must be same-origin; use the Vite proxy in development')
  }
  return resolved.href.replace(/\/$/, '')
}

const baseUrl = resolveApiBaseUrl(import.meta.env.VITE_API_BASE_URL)

async function request<T>(
  path: string,
  options: {
    method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
    body?: unknown
    idempotencyKey?: string
  } = {},
): Promise<T> {
  const method = options.method ?? 'GET'
  const headers = new Headers({ Accept: 'application/json' })
  if (options.body !== undefined) headers.set('Content-Type', 'application/json')
  if (options.idempotencyKey) headers.set('Idempotency-Key', options.idempotencyKey)
  if (method !== 'GET') {
    const csrf = readCsrfToken()
    if (csrf) headers.set('X-CSRF-Token', csrf)
  }
  const init: RequestInit = {
    method,
    headers,
    credentials: 'include',
  }
  if (options.body !== undefined) init.body = JSON.stringify(options.body)
  const response = await fetch(`${baseUrl}${path}`, init)
  if (response.status === 401) {
    window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT))
  }
  if (!response.ok) {
    let error: ErrorEnvelope
    try {
      error = (await response.json()) as ErrorEnvelope
    } catch {
      error = {}
    }
    const retryAfter = Number.parseInt(response.headers.get('Retry-After') ?? '', 10)
    throw new ApiRequestError(
      response.status,
      error.code ?? 'request_failed',
      error.message ?? `HTTP ${response.status}`,
      error.details ?? null,
      error.requestId ?? response.headers.get('X-Request-ID'),
      Number.isFinite(retryAfter) ? retryAfter : null,
    )
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

export function newIdempotencyKey(): string {
  return createIdempotencyKey(
    typeof globalThis.crypto === 'undefined' ? undefined : globalThis.crypto,
  )
}

let fallbackKeySequence = 0

export function createIdempotencyKey(provider: Crypto | undefined): string {
  if (typeof provider?.randomUUID === 'function') return provider.randomUUID()

  if (typeof provider?.getRandomValues === 'function') {
    const bytes = provider.getRandomValues(new Uint8Array(16))
    bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40
    bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80
    const value = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
    return [
      value.slice(0, 8),
      value.slice(8, 12),
      value.slice(12, 16),
      value.slice(16, 20),
      value.slice(20),
    ].join('-')
  }

  // An idempotency key is a collision guard, not an authentication secret. This
  // final fallback supports legacy browsers without Web Crypto at all.
  fallbackKeySequence = (fallbackKeySequence + 1) % Number.MAX_SAFE_INTEGER
  return [
    'local',
    Date.now().toString(36),
    fallbackKeySequence.toString(36),
    Math.random().toString(36).slice(2, 14),
  ].join('-')
}

export const api = {
  login: (input: LoginDto) =>
    request<SessionDto>('/api/v1/auth/login', { method: 'POST', body: input }),
  session: async () => {
    try {
      return await request<SessionDto>('/api/v1/auth/session')
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 401) return null
      throw error
    }
  },
  logout: () => request<void>('/api/v1/auth/logout', { method: 'POST' }),
  overview: () => request<OverviewDto>('/api/v1/overview'),
  hosts: () => request<HostDto[]>('/api/v1/hosts'),
  host: (id: string) => request<HostDto>(`/api/v1/hosts/${id}`),
  createHost: (input: HostCreateDto) =>
    request<HostDto>('/api/v1/hosts', { method: 'POST', body: input }),
  updateHost: (id: string, input: HostUpdateDto) =>
    request<HostDto>(`/api/v1/hosts/${id}`, { method: 'PUT', body: input }),
  deleteHost: (id: string) => request<void>(`/api/v1/hosts/${id}`, { method: 'DELETE' }),
  testHost: (id: string) =>
    request<RunDto>(`/api/v1/hosts/${id}/test`, {
      method: 'POST',
      idempotencyKey: newIdempotencyKey(),
    }),
  scanHostKeys: (id: string) =>
    request<HostKeyScanDto[]>(`/api/v1/hosts/${id}/host-keys/scan`, { method: 'POST' }),
  confirmHostKey: (id: string, value: { algorithm: string; fingerprint: string }) =>
    request<HostKeyDto>(`/api/v1/hosts/${id}/host-keys/confirm`, {
      method: 'POST',
      idempotencyKey: newIdempotencyKey(),
      body: value,
    }),
  createWebShellSession: (id: string) =>
    request<WebShellSessionDto>(`/api/v1/hosts/${id}/web-shell-sessions`, {
      method: 'POST',
    }),
  closeWebShellSession: (id: string) =>
    request<void>(`/api/v1/web-shell-sessions/${id}`, { method: 'DELETE' }),
  groups: () => request<HostGroupDto[]>('/api/v1/groups'),
  createGroup: (input: GroupDto) =>
    request<HostGroupDto>('/api/v1/groups', { method: 'POST', body: input }),
  updateGroup: (id: string, input: GroupDto) =>
    request<HostGroupDto>(`/api/v1/groups/${id}`, { method: 'PUT', body: input }),
  deleteGroup: (id: string) => request<void>(`/api/v1/groups/${id}`, { method: 'DELETE' }),
  credentials: () => request<CredentialDto[]>('/api/v1/credentials'),
  createCredential: (input: CredentialCreateDto) =>
    request<CredentialDto>('/api/v1/credentials', { method: 'POST', body: input }),
  rotateCredential: (id: string, input: CredentialRotateDto) =>
    request<CredentialDto>(`/api/v1/credentials/${id}/revisions`, {
      method: 'POST',
      body: input,
    }),
  deleteCredential: (id: string) =>
    request<void>(`/api/v1/credentials/${id}`, { method: 'DELETE' }),
  runs: (limit = 100) => request<RunDto[]>(`/api/v1/runs?limit=${limit}`),
  run: (id: string) => request<RunDetailDto>(`/api/v1/runs/${id}`),
  runEvents: (id: string, after = 0) =>
    request<RunEventDto[]>(`/api/v1/runs/${id}/events?after=${after}`),
  createCommandRun: (input: CommandRunDto) =>
    request<RunDto>('/api/v1/runs/commands', {
      method: 'POST',
      body: input,
      idempotencyKey: newIdempotencyKey(),
    }),
  createPlaybookRun: (input: PlaybookRunDto) =>
    request<RunDto>('/api/v1/runs/playbooks', {
      method: 'POST',
      body: input,
      idempotencyKey: newIdempotencyKey(),
    }),
  cancelRun: (id: string) =>
    request<RunDto>(`/api/v1/runs/${id}/cancel`, { method: 'POST' }),
  retryRun: (id: string) =>
    request<RunDto>(`/api/v1/runs/${id}/retry`, {
      method: 'POST',
      idempotencyKey: newIdempotencyKey(),
    }),
  playbooks: () => request<PlaybookDto[]>('/api/v1/playbooks'),
  playbookConfig: () => request<PlaybookConfigDto>('/api/v1/playbooks/config'),
  databasePlaybook: (id: string) =>
    request<DatabasePlaybookDto>(`/api/v1/playbooks/database/${id}`),
  createDatabasePlaybook: (input: DatabasePlaybookCreateDto) =>
    request<DatabasePlaybookDto>('/api/v1/playbooks/database', {
      method: 'POST',
      body: input,
    }),
  updateDatabasePlaybook: (id: string, input: DatabasePlaybookUpdateDto) =>
    request<DatabasePlaybookDto>(`/api/v1/playbooks/database/${id}`, {
      method: 'PUT',
      body: input,
    }),
  deleteDatabasePlaybook: (id: string, version: number) =>
    request<void>(`/api/v1/playbooks/database/${id}?version=${version}`, {
      method: 'DELETE',
    }),
  validatePlaybook: (input: PlaybookValidationDto) =>
    request<PlaybookValidationResultDto>('/api/v1/playbooks/validate', {
      method: 'POST',
      body: input,
    }),
  systemInfo: () => request<SystemInfoDto>('/api/v1/system/info'),
  systemDoctor: () => request<Record<string, unknown>>('/api/v1/system/doctor'),
}

export function resolveWebShellSocketUrl(
  streamPath: string,
  apiBaseUrl: string = baseUrl,
): string {
  const url = new URL(streamPath, apiBaseUrl)
  if (url.protocol === 'http:') url.protocol = 'ws:'
  else if (url.protocol === 'https:') url.protocol = 'wss:'
  else throw new Error('Web Shell stream must use the same HTTP origin')
  if (url.origin.replace(/^ws/, 'http') !== new URL(apiBaseUrl).origin) {
    throw new Error('Web Shell stream must use the same origin')
  }
  return url.href
}

export function webShellSocket(streamPath: string): WebSocket {
  return new WebSocket(resolveWebShellSocketUrl(streamPath))
}

export function runEventSource(runId: string, after = 0): EventSource {
  return new EventSource(
    `${baseUrl}/api/v1/runs/${runId}/events/stream?after=${after}`,
    { withCredentials: true },
  )
}
