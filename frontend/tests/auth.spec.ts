import { QueryClient } from '@tanstack/vue-query'
import { describe, expect, it, vi } from 'vitest'

import {
  AUTH_UNAUTHORIZED_EVENT,
  ApiRequestError,
  api,
  readCsrfToken,
  resolveApiBaseUrl,
} from '@/shared/api/client'
import {
  applySessionTransition,
  authErrorTranslationKey,
  authQueryKeys,
} from '@/features/auth/session'

describe('session API client', () => {
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
