import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createRouter, createMemoryHistory } from 'vue-router'
import AppHeader from '@/components/AppHeader.vue'
import { useAuthStore } from '@/stores/auth'
import { useHealthStore } from '@/stores/health'
import { http } from '@/api/http'
import type { HealthResponse } from '@/api/types'

describe('Screen 1 Shell Header Component (AppHeader.vue)', () => {
  let router: ReturnType<typeof createRouter>

  beforeEach(() => {
    setActivePinia(createPinia())
    router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/', name: 'home', component: { template: '<div>Home</div>' } },
        { path: '/login', name: 'login', component: { template: '<div>Login</div>' } }
      ]
    })
  })

  function createWrapper() {
    return mount(AppHeader, {
      global: {
        plugins: [router]
      }
    })
  }

  it('renders application branding and operator profile username', async () => {
    const authStore = useAuthStore()
    authStore.user = { id: 'uuid-1', username: 'sec_operator', role: 'ADMIN' }

    // Mock initial checkHealth call
    vi.spyOn(http, 'get').mockResolvedValueOnce({
      data: { status: 'UP', components: { database: 'UP', ollama: 'UP' } } as HealthResponse,
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any
    })

    const wrapper = createWrapper()
    await flushPromises()

    expect(wrapper.text()).toContain('Ospysin Platform')
    expect(wrapper.text()).toContain('Operator: sec_operator')
  })

  it('displays "[Ollama: READY]" with green styling when Ollama is UP', async () => {
    const healthStore = useHealthStore()
    vi.spyOn(healthStore, 'checkHealth').mockImplementation(async () => {
      healthStore.health = {
        status: 'UP',
        components: {
          database: 'UP',
          ollama: 'UP'
        }
      }
      return healthStore.health
    })

    const wrapper = createWrapper()
    await flushPromises()

    const badge = wrapper.find('[data-testid="health-badge"]')
    expect(badge.text()).toContain('[Ollama: READY]')
    expect(badge.classes()).toContain('text-emerald-400')
  })

  it('displays "[Ollama: OFFLINE]" with red styling when Ollama is DOWN', async () => {
    const healthStore = useHealthStore()
    vi.spyOn(healthStore, 'checkHealth').mockImplementation(async () => {
      healthStore.health = {
        status: 'DOWN',
        components: {
          database: 'UP',
          ollama: 'DOWN'
        }
      }
      return healthStore.health
    })

    const wrapper = createWrapper()
    await flushPromises()

    const badge = wrapper.find('[data-testid="health-badge"]')
    expect(badge.text()).toContain('[Ollama: OFFLINE]')
    expect(badge.classes()).toContain('text-rose-400')
  })

  it('invokes authStore.logout() and navigates to /login when [Logout] button is clicked', async () => {
    const authStore = useAuthStore()
    authStore.user = { id: 'admin-1', username: 'admin', role: 'ADMIN' }
    authStore.status = 'authenticated'

    const logoutSpy = vi.spyOn(authStore, 'logout').mockResolvedValueOnce()
    const pushSpy = vi.spyOn(router, 'push')

    // Mock checkHealth
    vi.spyOn(http, 'get').mockResolvedValueOnce({
      data: { status: 'UP', components: { database: 'UP', ollama: 'UP' } },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any
    })

    const wrapper = createWrapper()
    await flushPromises()

    const logoutBtn = wrapper.find('[data-testid="logout-button"]')
    expect(logoutBtn.exists()).toBe(true)
    await logoutBtn.trigger('click')
    await flushPromises()

    expect(logoutSpy).toHaveBeenCalledTimes(1)
    expect(pushSpy).toHaveBeenCalledWith('/login')
  })
})
