import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import { createRouter, createMemoryHistory } from 'vue-router'
import SessionWorkspaceView from '@/views/SessionWorkspaceView.vue'
import { useSessionsStore } from '@/stores/sessions'
import { http, ApiError } from '@/api/http'
import type { AuditSession } from '@/api/types'

describe('Screen 3 Shell: Session Workspace View (SessionWorkspaceView.vue)', () => {
  let router: ReturnType<typeof createRouter>

  const mockSession: AuditSession = {
    id: 'test-session-123',
    targetUrl: 'https://example.com',
    mode: 'PUBLIC',
    state: 'ACTIVE',
    scopeAcknowledged: true,
    scopeAckVersion: '1.0.0',
    scopeAckHash: 'hash-abc',
    scopeAckTimestamp: '2026-10-09T01:40:00Z',
    stepCount: 5,
    findingCount: 1,
    createdAt: '2026-10-09T01:40:00Z',
    updatedAt: '2026-10-09T01:40:00Z'
  }

  beforeEach(() => {
    setActivePinia(createPinia())
    router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/', name: 'home', component: { template: '<div>Home</div>' } },
        {
          path: '/sessions/:id',
          name: 'session-workspace',
          component: SessionWorkspaceView
        }
      ]
    })

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
      if (url.includes('/sessions/test-session-123')) {
        return {
          data: mockSession,
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any
        }
      }
      throw new ApiError({
        title: 'Session Not Found',
        status: 404,
        detail: 'Session does not exist'
      })
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  async function createWrapper(sessionId = 'test-session-123') {
    await router.push(`/sessions/${sessionId}`)
    await router.isReady()
    return mount(SessionWorkspaceView, {
      global: {
        plugins: [router]
      }
    })
  }

  it('loads session on mount and renders target URL, mode badge, and state badge', async () => {
    const wrapper = await createWrapper()
    await flushPromises()

    expect(wrapper.find('[data-testid="workspace-target-url"]').text()).toBe('https://example.com')
    expect(wrapper.find('[data-testid="workspace-mode-badge"]').text()).toBe('PUBLIC')
    expect(wrapper.find('[data-testid="workspace-state-badge"]').text()).toBe('ACTIVE')
    expect(wrapper.find('[data-testid="complete-session-button"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="abort-session-button"]').exists()).toBe(true)
  })

  it('calls completeSession when Complete Session button is clicked', async () => {
    const store = useSessionsStore()
    const completeSpy = vi.spyOn(store, 'completeSession').mockResolvedValue({
      ...mockSession,
      state: 'COMPLETED'
    })

    const wrapper = await createWrapper()
    await flushPromises()

    await wrapper.find('[data-testid="complete-session-button"]').trigger('click')
    expect(completeSpy).toHaveBeenCalledWith('test-session-123')
  })

  it('calls abortSession when Abort Session button is clicked', async () => {
    const store = useSessionsStore()
    const abortSpy = vi.spyOn(store, 'abortSession').mockResolvedValue({
      ...mockSession,
      state: 'ABORTED'
    })

    const wrapper = await createWrapper()
    await flushPromises()

    await wrapper.find('[data-testid="abort-session-button"]').trigger('click')
    expect(abortSpy).toHaveBeenCalledWith('test-session-123')
  })

  it('navigates back to home when Back button is clicked', async () => {
    const pushSpy = vi.spyOn(router, 'push')
    const wrapper = await createWrapper()
    await flushPromises()

    await wrapper.find('[data-testid="back-to-sessions-button"]').trigger('click')
    expect(pushSpy).toHaveBeenCalledWith('/')
  })

  it('renders error card when session fetch returns 404', async () => {
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
      throw new ApiError({
        title: 'Session Not Found',
        status: 404,
        detail: 'Session does not exist'
      })
    })

    const wrapper = await createWrapper('non-existent-id')
    await flushPromises()

    expect(wrapper.find('[data-testid="workspace-error-card"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('Session Not Found')
    expect(wrapper.text()).toContain('Session does not exist')
  })

  it('displays workspace-action-error banner on 409 Conflict during completeSession while keeping workspace visible', async () => {
    const store = useSessionsStore()
    const conflictProblem = {
      title: 'Session Conflict',
      status: 409,
      detail: 'Cannot complete session while 1 executions are PENDING or RUNNING'
    }

    vi.spyOn(store, 'completeSession').mockImplementation(async () => {
      store.error = conflictProblem
      throw new ApiError(conflictProblem)
    })

    const wrapper = await createWrapper('test-session-123')
    await flushPromises()

    await wrapper.find('[data-testid="complete-session-button"]').trigger('click')
    await flushPromises()

    // Workspace remains visible
    expect(wrapper.find('[data-testid="workspace-target-url"]').exists()).toBe(true)
    // Action error banner is rendered with RFC 9457 details
    const actionError = wrapper.find('[data-testid="workspace-action-error"]')
    expect(actionError.exists()).toBe(true)
    expect(actionError.text()).toContain('Session Conflict')
    expect(actionError.text()).toContain('Cannot complete session while 1 executions are PENDING or RUNNING')

    // Dismiss button clears error
    await wrapper.find('[data-testid="dismiss-action-error-button"]').trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.find('[data-testid="workspace-action-error"]').exists()).toBe(false)
  })

  it('clears currentSession and renders workspace-error-card when navigating from valid session to 404 session', async () => {
    const store = useSessionsStore()
    const wrapper = await createWrapper('test-session-123')
    await flushPromises()

    // Valid session is loaded
    expect(wrapper.find('[data-testid="workspace-target-url"]').text()).toBe('https://example.com')
    expect(store.currentSession).not.toBeNull()

    // Now navigate to 404 route
    await router.push('/sessions/non-existent-id')
    await flushPromises()

    expect(store.currentSession).toBeNull()
    expect(wrapper.find('[data-testid="workspace-error-card"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('Session Not Found')
  })
})
