import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import LoginView from '@/views/LoginView.vue'
import HomeView from '@/views/HomeView.vue'
import SessionWorkspaceView from '@/views/SessionWorkspaceView.vue'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: LoginView,
    meta: { guestOnly: true }
  },
  {
    path: '/',
    name: 'home',
    component: HomeView,
    meta: { requiresAuth: true }
  },
  {
    path: '/sessions/:id',
    name: 'session-workspace',
    component: SessionWorkspaceView,
    meta: { requiresAuth: true }
  },
  {
    path: '/sessions/:id/report',
    name: 'session-report',
    component: () => import('@/views/SessionReportView.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/'
  }
]

export const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes
})

router.beforeEach(async (to, _from, next) => {
  const authStore = useAuthStore()

  if (authStore.status === 'idle') {
    await authStore.fetchCurrentUser()
  }

  const isAuthenticated = authStore.status === 'authenticated'

  if (to.meta.requiresAuth && !isAuthenticated) {
    next({ name: 'login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : undefined })
  } else if (to.meta.guestOnly && isAuthenticated) {
    next({ name: 'home' })
  } else {
    next()
  }
})

export default router
