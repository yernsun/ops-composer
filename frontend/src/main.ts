import { VueQueryPlugin } from '@tanstack/vue-query'
import Aura from '@primeuix/themes/aura'
import { createPinia } from 'pinia'
import PrimeVue from 'primevue/config'
import ConfirmationService from 'primevue/confirmationservice'
import 'primeicons/primeicons.css'
import ToastService from 'primevue/toastservice'
import { createApp } from 'vue'

import App from './app/App.vue'
import { router } from './router'
import { i18n, initialLocale, primeLocales } from './shared/i18n'
import { applyTheme, readThemePreference } from './shared/theme'
import './styles.css'

applyTheme(readThemePreference())

createApp(App)
  .use(createPinia())
  .use(i18n)
  .use(VueQueryPlugin)
  .use(router)
  .use(PrimeVue, {
    theme: {
      preset: Aura,
      options: { darkModeSelector: '.app-dark' },
    },
    locale: primeLocales[initialLocale],
    ripple: true,
  })
  .use(ToastService)
  .use(ConfirmationService)
  .mount('#app')
