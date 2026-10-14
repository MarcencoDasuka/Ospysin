import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import { createRouter, createMemoryHistory } from 'vue-router'
import HomeView from '@/views/HomeView.vue'
import { useSessionsStore } from '@/stores/sessions'
import { http } from '@/api/http'
import type { AuditSession, SessionPageResponse } from '@/api/types'

describe('Screen 1: Session List View Component (HomeView.vue)', () => {
  let router: ReturnType<typeof createRouter>

  const mockSessions: AuditSession[] = [
    {
      id: 'session-uuid-1',
      targetUrl: 'https://example.com',
      mode: 'PUBLIC',
      state: 'ACTIVE',
      scopeAcknowledged: true,
      scopeAckVersion: '1.0.0',
      scopeAckHash: 'hash1',
      scopeAckTimestamp: '2026-10-09T01:20:00Z',
      stepCount: 4,
      findingCount: 2,
      createdAt: '2026-10-09T01:20:00Z',
      updatedAt: '2026-10-09T01:20:00Z'
    },
    {
      id: 'session-uuid-2',
      targetUrl: 'http://192.168.1.50:8080',
      mode: 'LOCAL',
      state: 'COMPLETED',
      scopeAcknowledged: true,
      scopeAckVersion: '1.0.0',
      scopeAckHash: 'hash2',
      scopeAckTimestamp: '2026-10-08T19:15:00Z',
      stepCount: 7,
      findingCount: 0,
      createdAt: '2026-10-08T19:15:00Z',
      updatedAt: '2026-10-08T19:15:00Z'
    }
  ]

  beforeEach(() => {
    setActivePinia(createPinia())
    router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/', name: 'home', component: HomeView },
        {
          path: '/sessions/:id',
          name: 'session-workspace',
          component: { template: '<div>Workspace</div>' }
        }
      ]
    })

    // Mock background health check called by AppHeader
    vi.spyOn(http, 'get').mockImplementation(async (url: string) => {
      if (url.includes('/health')) {
        return {
          data: { status: 'UP', components: { database: 'UP', ollama: 'UP' } },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any
        }
      }
      return {
        data: { content: [], page: 0, size: 20, totalElements: 0, totalPages: 0 },
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any
      }
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  function createWrapper() {
    return mount(HomeView, {
      global: {
        plugins: [router]
      }
    })
  }

  it('renders table columns and displays empty state when no sessions exist', async () => {
    const wrapper = createWrapper()
    await flushPromises()

    expect(wrapper.find('[data-testid="sessions-table"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="empty-sessions-state"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('No active audit sessions found')
    expect(wrapper.findAll('[data-testid="session-row"]').length).toBe(0)
  })

  it('renders session rows with target URL, mode badge, state, steps, and findings', async () => {
    const pageResponse: SessionPageResponse = {
      content: mockSessions,
      page: 0,
      size: 20,
      totalElements: 2,
      totalPages: 1
    }

    vi.spyOn(http, 'get').mockImplementation(async (url: string) => {
      if (url.includes('/health')) {
        return {
          data: { status: 'UP', components: { database: 'UP', ollama: 'UP' } },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any
        }
      }
      return {
        data: pageResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any
      }
    })

    const wrapper = createWrapper()
    await flushPromises()

    const rows = wrapper.findAll('[data-testid="session-row"]')
    expect(rows.length).toBe(2)

    // First row assertions
    const row1 = rows[0]
    expect(row1.find('[data-testid="session-target-url"]').text()).toBe('https://example.com')
    expect(row1.find('[data-testid="session-mode-badge"]').text()).toBe('PUBLIC')
    expect(row1.find('[data-testid="session-state-badge"]').text()).toBe('ACTIVE')
    expect(row1.find('[data-testid="session-steps-count"]').text()).toBe('4')
    expect(row1.find('[data-testid="session-findings-count"]').text()).toBe('2')
    expect(row1.find('[data-testid="open-session-button"]').exists()).toBe(true)

    // Second row assertions
    const row2 = rows[1]
    expect(row2.find('[data-testid="session-target-url"]').text()).toBe('http://192.168.1.50:8080')
    expect(row2.find('[data-testid="session-mode-badge"]').text()).toBe('LOCAL')
    expect(row2.find('[data-testid="session-state-badge"]').text()).toBe('COMPLETED')
  })

  it('navigates to workspace when [Open] button is clicked', async () => {
    const pageResponse: SessionPageResponse = {
      content: mockSessions,
      page: 0,
      size: 20,
      totalElements: 2,
      totalPages: 1
    }

    vi.spyOn(http, 'get').mockImplementation(async (url: string) => {
      if (url.includes('/health')) {
        return {
          data: { status: 'UP', components: { database: 'UP', ollama: 'UP' } },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any
        }
      }
      return {
        data: pageResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any
      }
    })

    const pushSpy = vi.spyOn(router, 'push')
    const wrapper = createWrapper()
    await flushPromises()

    const openButtons = wrapper.findAll('[data-testid="open-session-button"]')
    expect(openButtons.length).toBe(2)

    await openButtons[0].trigger('click')
    expect(pushSpy).toHaveBeenCalledWith('/sessions/session-uuid-1')

    await openButtons[1].trigger('click')
    expect(pushSpy).toHaveBeenCalledWith('/sessions/session-uuid-2')
  })

  it('opens NewSessionModal when [+ New Audit Session] button is clicked', async () => {
    const wrapper = createWrapper()
    await flushPromises()

    const newBtn = wrapper.find('[data-testid="new-session-button"]')
    expect(newBtn.exists()).toBe(true)

    await newBtn.trigger('click')
    await wrapper.vm.$nextTick()

    // Modal dialog becomes visible
    expect(wrapper.find('[role="dialog"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="target-url-input"]').exists()).toBe(true)
  })

  it('navigates to workspace and closes modal when session is created', async () => {
    const pushSpy = vi.spyOn(router, 'push')
    const wrapper = createWrapper()
    await flushPromises()

    // Open modal
    await wrapper.find('[data-testid="new-session-button"]').trigger('click')
    await wrapper.vm.$nextTick()

    // Find modal child and trigger created event
    const modalComponent = wrapper.findComponent({ name: 'NewSessionModal' })
    expect(modalComponent.exists()).toBe(true)

    modalComponent.vm.$emit('created', mockSessions[0])
    await flushPromises()

    expect(pushSpy).toHaveBeenCalledWith('/sessions/session-uuid-1')
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false)
  })

  it('renders pagination controls and triggers page navigation when totalPages > 1', async () => {
    const store = useSessionsStore()
    store.sessions = [mockSessions[0]]
    store.page = 0
    store.size = 1
    store.totalElements = 2
    store.totalPages = 2

    const fetchSpy = vi.spyOn(store, 'fetchSessions').mockResolvedValue({
      content: [mockSessions[1]],
      page: 1,
      size: 1,
      totalElements: 2,
      totalPages: 2
    })

    const wrapper = createWrapper()
    await flushPromises()

    expect(wrapper.find('[data-testid="pagination-controls"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="page-indicator"]').text()).toBe('Page 1 of 2')

    const prevBtn = wrapper.find('[data-testid="prev-page-button"]')
    const nextBtn = wrapper.find('[data-testid="next-page-button"]')

    expect(prevBtn.attributes('disabled')).toBeDefined()
    expect(nextBtn.attributes('disabled')).toBeUndefined()

    await nextBtn.trigger('click')
    expect(fetchSpy).toHaveBeenCalledWith(1, 1)
  })

  it('hides sessions-list-error banner while NewSessionModal is open to prevent error bleed', async () => {
    const store = useSessionsStore()
    const wrapper = createWrapper()
    await flushPromises()

    store.error = { title: 'Policy Error', status: 403, detail: 'IP rejected' }
    await wrapper.vm.$nextTick()

    // While modal is closed, error banner is visible
    expect(wrapper.find('[data-testid="sessions-list-error"]').exists()).toBe(true)

    // Open modal
    await wrapper.find('[data-testid="new-session-button"]').trigger('click')
    await wrapper.vm.$nextTick()

    // Error banner in list must be hidden while modal is open
    expect(wrapper.find('[data-testid="sessions-list-error"]').exists()).toBe(false)
  })

  it('handles pagination failure gracefully without unhandled promise rejection', async () => {
    const store = useSessionsStore()
    store.sessions = [mockSessions[0]]
    store.page = 1
    store.size = 1
    store.totalElements = 2
    store.totalPages = 2

    vi.spyOn(store, 'fetchSessions').mockRejectedValue(
      new Error('Network pagination error')
    )

    const wrapper = createWrapper()
    await flushPromises()

    const prevBtn = wrapper.find('[data-testid="prev-page-button"]')
    expect(prevBtn.attributes('disabled')).toBeUndefined()

    // Clicking prev should not throw unhandled rejection
    await expect(prevBtn.trigger('click')).resolves.not.toThrow()
  })
})
