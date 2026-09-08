import { type QueryClient, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, onMounted, onScopeDispose } from 'vue'

import {
  AUTH_UNAUTHORIZED_EVENT,
  AUTH_PERMISSIONS_CHANGED_EVENT,
  ApiRequestError,
  api,
  type SessionDto,
} from '@/shared/api/client'

export const authQueryKeys = {
  session: ['auth', 'session'] as const,
}

export type AuthState = 'loading' | 'guest' | 'authenticated'

const stableAuthErrorCodes = new Set([
  'authentication_required',
  'invalid_credentials',
  'invalid_or_expired_session',
  'origin_not_allowed',
  'csrf_failed',
  'auth_rate_limited',
  'totp_disabled',
  'request_validation_failed',
])

export function authErrorTranslationKey(error: unknown): string | null {
  if (!(error instanceof ApiRequestError) || !stableAuthErrorCodes.has(error.code)) return null
  return `auth.errors.${error.code}`
}

export async function applySessionTransition(
  queryClient: QueryClient,
  session: SessionDto | null,
): Promise<void> {
  queryClient.setQueryData(authQueryKeys.session, session)
  await queryClient.invalidateQueries({ queryKey: authQueryKeys.session, refetchType: 'none' })
}

export function useSessionState() {
  const queryClient = useQueryClient()
  const sessionQuery = useQuery({
    queryKey: authQueryKeys.session,
    queryFn: api.session,
    retry: false,
    staleTime: 60_000,
  })
  const session = computed<SessionDto | null>(() => sessionQuery.data.value ?? null)
  const state = computed<AuthState>(() => {
    if (sessionQuery.isPending.value) return 'loading'
    return session.value ? 'authenticated' : 'guest'
  })

  function markGuest(): void {
    queryClient.setQueryData(authQueryKeys.session, null)
    queryClient.removeQueries({ predicate: ({ queryKey }) => queryKey[0] !== 'auth' })
  }

  function refreshPermissions(): void {
    void queryClient.invalidateQueries({ queryKey: authQueryKeys.session })
  }

  onMounted(() => {
    window.addEventListener(AUTH_UNAUTHORIZED_EVENT, markGuest)
    window.addEventListener(AUTH_PERMISSIONS_CHANGED_EVENT, refreshPermissions)
  })
  onScopeDispose(() => {
    window.removeEventListener(AUTH_UNAUTHORIZED_EVENT, markGuest)
    window.removeEventListener(AUTH_PERMISSIONS_CHANGED_EVENT, refreshPermissions)
  })

  return { sessionQuery, session, state, markGuest }
}
