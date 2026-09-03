# Frontend and i18n

Vue Query owns server state and invalidation. Pinia is limited to browser-owned state such as theme
and locale. Authentication has one login form and session restore; there is no signup, workspace
selector, or browser-managed authorization state.

The application uses PrimeVue 4 APIs and the Aura preset. Prefer PrimeVue inputs, Select,
DataTable, Drawer, Dialog/ConfirmDialog, Toast, Tabs, Tag, and loading primitives over bespoke
widgets. Keep labels associated with controls, provide table empty/loading states, preserve keyboard
focus, and make destructive or Shell actions explicit confirmations.

All display copy belongs in both `zh-CN` and `en-US` catalogs. `.vue` files must not contain direct
Chinese display strings. Run `npm run i18n:check` after adding or removing a key.

The generated OpenAPI type file is `src/shared/api/schema.d.ts`. The browser client uses same-origin
`/api/v1` requests, includes cookies, and copies the readable CSRF cookie into `X-CSRF-Token` for
mutations. RunEvent streaming uses one `run-event` SSE event whose payload contains `eventType` and
`sequence`; reconnects continue from the highest persisted sequence.

Production assets are built into the Python/Ansible image and served by FastAPI with SPA history
fallback. Vite's proxy exists only for local development. Route-level dynamic imports keep page
bundles independent.
