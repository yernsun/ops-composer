import { QueryClient } from '@tanstack/vue-query'
import { describe, expect, it, vi } from 'vitest'

import {
  AUTH_UNAUTHORIZED_EVENT,
  ApiRequestError,
  api,
  createIdempotencyKey,
  newIdempotencyKey,
  readCsrfToken,
  resolveApiBaseUrl,
  runEventSource,
} from '@/shared/api/client'
import {
  applySessionTransition,
  authErrorTranslationKey,
  authQueryKeys,
} from '@/features/auth/session'

describe('session API client', () => {
  it('uses randomUUID when it is available', () => {
    const provider = {
      randomUUID: vi.fn(() => '13fa9b80-370c-4d2a-9bec-a80b78c71985'),
    } as unknown as Crypto

    expect(createIdempotencyKey(provider)).toBe('13fa9b80-370c-4d2a-9bec-a80b78c71985')
    expect(provider.randomUUID).toHaveBeenCalledOnce()
  })

  it('creates an RFC 4122 v4 key when randomUUID is unavailable over LAN HTTP', () => {
    const provider = {
      getRandomValues: vi.fn((bytes: Uint8Array) => {
        bytes.set(Array.from({ length: 16 }, (_, index) => index))
        return bytes
      }),
    } as unknown as Crypto

    const key = createIdempotencyKey(provider)

    expect(key).toBe('00010203-0405-4607-8809-0a0b0c0d0e0f')
    expect(key).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  })

  it('still creates a valid idempotency key without Web Crypto', () => {
    expect(createIdempotencyKey(undefined).length).toBeGreaterThanOrEqual(8)
  })

  it('keeps browser API traffic on the same origin', () => {
    expect(resolveApiBaseUrl('', 'http://172.20.0.10:8173')).toBe(
      'http://172.20.0.10:8173',
    )
    expect(resolveApiBaseUrl('/ops/', 'http://172.20.0.10:8173')).toBe(
      'http://172.20.0.10:8173/ops',
    )
    expect(() =>
      resolveApiBaseUrl('http://172.20.0.11:8000', 'http://172.20.0.10:8173'),
    ).toThrow('must be same-origin')
  })

  it('prefers the production CSRF cookie and sends it on unsafe requests', async () => {
    vi.spyOn(document, 'cookie', 'get').mockReturnValue(
      '__Host-ops-composer-csrf=production-token; ops-composer-csrf=dev-token',
    )
    let captured: RequestInit | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: string, init?: RequestInit) => {
        captured = init
        return new Response(null, { status: 204 })
      }),
    )

    await api.logout()

    expect(readCsrfToken()).toBe('production-token')
    expect(new Headers(captured?.headers).get('X-CSRF-Token')).toBe('production-token')
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('ignores a malformed readable CSRF cookie', () => {
    vi.spyOn(document, 'cookie', 'get').mockReturnValue('ops-composer-csrf=%broken')
    expect(readCsrfToken()).toBeNull()
    vi.restoreAllMocks()
  })

  it('maps every M1 client operation to the same-origin HTTP contract', async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        requests.push({ url: String(input), ...(init ? { init } : {}) })
        return new Response('{}', {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }),
    )

    await Promise.all([
      api.login({ username: 'admin', password: 'test-password' }),
      api.session(),
      api.logout(),
      api.overview(),
      api.hosts(),
      api.createHost({} as Parameters<typeof api.createHost>[0]),
      api.updateHost('host-1', {} as Parameters<typeof api.updateHost>[1]),
      api.deleteHost('host-1'),
      api.testHost('host-1'),
      api.scanHostKeys('host-1'),
      api.confirmHostKey('host-1', {
        algorithm: 'ssh-ed25519',
        fingerprint: 'SHA256:test',
      }),
      api.groups(),
      api.createGroup({} as Parameters<typeof api.createGroup>[0]),
      api.updateGroup('group-1', {} as Parameters<typeof api.updateGroup>[1]),
      api.deleteGroup('group-1'),
      api.credentials(),
      api.createCredential({} as Parameters<typeof api.createCredential>[0]),
      api.rotateCredential(
        'credential-1',
        {} as Parameters<typeof api.rotateCredential>[1],
      ),
      api.deleteCredential('credential-1'),
      api.runs(25),
      api.run('run-1'),
      api.runEvents('run-1', 7),
      api.createCommandRun({} as Parameters<typeof api.createCommandRun>[0]),
      api.createPlaybookRun({} as Parameters<typeof api.createPlaybookRun>[0]),
      api.cancelRun('run-1'),
      api.retryRun('run-1'),
      api.playbooks(),
      api.validatePlaybook('playbooks/site.yml'),
      api.systemInfo(),
      api.systemDoctor(),
    ])

    expect(requests).toHaveLength(30)
    expect(requests.every(({ url }) => url.startsWith(window.location.origin))).toBe(true)
    expect(requests.find(({ url }) => url.includes('/runs?limit=25'))).toBeDefined()
    expect(newIdempotencyKey().length).toBeGreaterThanOrEqual(8)

    class FakeEventSource {
      constructor(
        readonly url: string,
        readonly options: EventSourceInit,
      ) {}
    }
    vi.stubGlobal('EventSource', FakeEventSource)
    const source = runEventSource('run-1', 7) as unknown as FakeEventSource
    expect(source.url).toContain('/runs/run-1/events/stream?after=7')
    expect(source.options.withCredentials).toBe(true)
  })

  it('turns a 401 session response into guest state and emits the global signal', async () => {
    const unauthorized = vi.fn()
    window.addEventListener(AUTH_UNAUTHORIZED_EVENT, unauthorized)
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            code: 'authentication_required',
            message: 'authentication required',
          }),
          { status: 401, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )

    await expect(api.session()).resolves.toBeNull()
    expect(unauthorized).toHaveBeenCalledOnce()
    window.removeEventListener(AUTH_UNAUTHORIZED_EVENT, unauthorized)
    vi.unstubAllGlobals()
  })

  it('seeds and invalidates the session boundary after authentication changes', async () => {
    const queryClient = new QueryClient()
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const session = {
      userId: '00000000-0000-4000-8000-000000000001',
      username: 'admin',
      expiresAt: '2026-01-02T00:00:00Z',
    }

    await applySessionTransition(queryClient, session)

    expect(queryClient.getQueryData(authQueryKeys.session)).toEqual(session)
    expect(invalidate).toHaveBeenCalledWith({
      queryKey: authQueryKeys.session,
      refetchType: 'none',
    })
  })

  it.each([
    'authentication_required',
    'invalid_credentials',
    'invalid_or_expired_session',
    'origin_not_allowed',
    'csrf_failed',
    'auth_rate_limited',
    'request_validation_failed',
  ])('maps the stable %s error code to a locale key', (code) => {
    const error = new ApiRequestError(401, code, 'safe message', null, null, null)
    expect(authErrorTranslationKey(error)).toBe(`auth.errors.${code}`)
  })
})
