import { useQuery } from '@tanstack/vue-query'
import { computed } from 'vue'

import { api, type PermissionDto, type SessionDto } from '@/shared/api/client'

import { authQueryKeys } from './session'

export function hasPermission(
  session: SessionDto | null | undefined,
  permission: PermissionDto,
): boolean {
  return session?.permissions.includes(permission) ?? false
}

export function useAuthorization() {
  const sessionQuery = useQuery({
    queryKey: authQueryKeys.session,
    queryFn: api.session,
    staleTime: 60_000,
  })
  const session = computed(() => sessionQuery.data.value ?? null)
  const can = (permission: PermissionDto) => hasPermission(session.value, permission)
  const totpPolicyEnabled = computed(() => session.value?.totpPolicyEnabled ?? true)
  const elevated = computed(() => {
    const value = session.value?.elevatedUntil
    return value !== null && value !== undefined && new Date(value).getTime() > Date.now()
  })
  return { session, sessionQuery, can, elevated, totpPolicyEnabled }
}
