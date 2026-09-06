import { createRouter, createWebHistory } from 'vue-router'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'overview', component: () => import('@/pages/DashboardPage.vue') },
    { path: '/hosts', name: 'hosts', component: () => import('@/pages/HostsPage.vue') },
    {
      path: '/hosts/:hostId/shell',
      name: 'web-shell',
      component: () => import('@/pages/WebShellPage.vue'),
      props: true,
      meta: { layout: 'terminal' },
    },
    { path: '/groups', name: 'groups', component: () => import('@/pages/GroupsPage.vue') },
    { path: '/credentials', name: 'credentials', component: () => import('@/pages/CredentialsPage.vue') },
    { path: '/commands', name: 'commands', component: () => import('@/pages/CommandPage.vue') },
    { path: '/playbooks', name: 'playbooks', component: () => import('@/pages/PlaybooksPage.vue') },
    { path: '/runs', name: 'runs', component: () => import('@/pages/RunsPage.vue') },
    { path: '/runs/:id', name: 'run-detail', component: () => import('@/pages/RunDetailPage.vue'), props: true },
    { path: '/system', name: 'system', component: () => import('@/pages/SystemPage.vue') },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
  scrollBehavior: () => ({ top: 0 }),
})
