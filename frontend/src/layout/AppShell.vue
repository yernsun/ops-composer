<script setup lang="ts">
import { useMutation, useQueryClient } from '@tanstack/vue-query'
import Avatar from 'primevue/avatar'
import Button from 'primevue/button'
import ConfirmDialog from 'primevue/confirmdialog'
import Drawer from 'primevue/drawer'
import Select from 'primevue/select'
import Toast from 'primevue/toast'
import { usePrimeVue } from 'primevue/config'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterLink, RouterView, useRoute } from 'vue-router'

import { applySessionTransition } from '@/features/auth/session'
import { api, type SessionDto } from '@/shared/api/client'
import { supportedLocales, type AppLocale } from '@/shared/i18n'
import { useLocaleStore } from '@/shared/stores/locale'
import { useThemeStore } from '@/shared/stores/theme'
import { themePreferences, type ThemePreference } from '@/shared/theme'

defineProps<{ session: SessionDto }>()

const { t } = useI18n()
const queryClient = useQueryClient()
const route = useRoute()
const primeVue = usePrimeVue()
const localeStore = useLocaleStore()
const themeStore = useThemeStore()
const mobileOpen = ref(false)

const navItems = [
  { to: '/', label: 'nav.overview', icon: 'pi pi-home' },
  { to: '/hosts', label: 'nav.hosts', icon: 'pi pi-server' },
  { to: '/groups', label: 'nav.groups', icon: 'pi pi-sitemap' },
  { to: '/credentials', label: 'nav.credentials', icon: 'pi pi-key' },
  { to: '/commands', label: 'nav.commands', icon: 'pi pi-terminal' },
  { to: '/playbooks', label: 'nav.playbooks', icon: 'pi pi-book' },
  { to: '/runs', label: 'nav.runs', icon: 'pi pi-history' },
  { to: '/system', label: 'nav.system', icon: 'pi pi-cog' },
] as const

const localeOptions = supportedLocales.map((value) => ({ value, label: value }))
const themeOptions = themePreferences.map((value) => ({ value, label: value }))
const currentTitle = computed(
  () => navItems.find((item) => item.to === route.path)?.label ?? 'nav.runs',
)

const logoutMutation = useMutation({
  mutationFn: api.logout,
  onSettled: async () => {
    await applySessionTransition(queryClient, null)
  },
})

function setLocale(value: AppLocale): void {
  localeStore.setLocale(value, primeVue)
}

function setTheme(value: ThemePreference): void {
  themeStore.setTheme(value)
}

onMounted(themeStore.start)
onBeforeUnmount(themeStore.stop)
</script>

<template>
  <div class="console-shell">
    <Toast position="top-right" />
    <ConfirmDialog />

    <aside class="sidebar desktop-sidebar">
      <div class="sidebar-brand">
        <span class="brand-icon"><i class="pi pi-sparkles" /></span>
        <span><strong>OpsComposer</strong><small>{{ t('app.shortTagline') }}</small></span>
      </div>
      <nav class="main-nav" :aria-label="t('nav.primary')">
        <RouterLink
          v-for="item in navItems"
          :key="item.to"
          :to="item.to"
          :class="{ active: route.path === item.to || (item.to === '/runs' && route.path.startsWith('/runs/')) }"
        >
          <i :class="item.icon" />
          <span>{{ t(item.label) }}</span>
        </RouterLink>
      </nav>
      <div class="sidebar-foot">
        <i class="pi pi-database" />
        <div><strong>PostgreSQL</strong><small>{{ t('app.onlyDependency') }}</small></div>
      </div>
    </aside>

    <Drawer v-model:visible="mobileOpen" class="mobile-drawer" :header="t('nav.primary')">
      <nav class="main-nav">
        <RouterLink
          v-for="item in navItems"
          :key="item.to"
          :to="item.to"
          @click="mobileOpen = false"
        >
          <i :class="item.icon" /><span>{{ t(item.label) }}</span>
        </RouterLink>
      </nav>
    </Drawer>

    <div class="console-main">
      <header class="console-topbar">
        <div class="topbar-title">
          <Button
            class="mobile-menu"
            icon="pi pi-bars"
            severity="secondary"
            text
            rounded
            :aria-label="t('nav.open')"
            @click="mobileOpen = true"
          />
          <div>
            <span>{{ t('app.productName') }}</span>
            <h1>{{ t(currentTitle) }}</h1>
          </div>
        </div>
        <div class="topbar-actions">
          <Select
            :model-value="localeStore.locale"
            :options="localeOptions"
            option-label="label"
            option-value="value"
            :aria-label="t('app.language')"
            size="small"
            @update:model-value="setLocale"
          />
          <Select
            :model-value="themeStore.preference"
            :options="themeOptions"
            option-label="label"
            option-value="value"
            :aria-label="t('app.theme')"
            size="small"
            @update:model-value="setTheme"
          >
            <template #value="{ value }">{{ t(`themes.${value}`) }}</template>
            <template #option="{ option }">{{ t(`themes.${option.value}`) }}</template>
          </Select>
          <Avatar icon="pi pi-user" shape="circle" />
          <span class="user-name">{{ session.username }}</span>
          <Button
            icon="pi pi-sign-out"
            severity="secondary"
            text
            rounded
            :loading="logoutMutation.isPending.value"
            :aria-label="t('auth.logout')"
            @click="logoutMutation.mutate()"
          />
        </div>
      </header>
      <main class="page-content">
        <RouterView />
      </main>
    </div>
  </div>
</template>
