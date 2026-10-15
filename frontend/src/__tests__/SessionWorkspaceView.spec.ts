import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import { createRouter, createMemoryHistory } from 'vue-router'
import SessionWorkspaceView from '@/views/SessionWorkspaceView.vue'
import { useSessionsStore } from '@/stores/sessions'
import { useWorkspaceStore } from '@/stores/workspace'
import { http, ApiError } from '@/api/http'
import type {
  AuditSession,
  ToolMetadata,
  StepSummaryResponse,
  StepDetailResponse
} from '@/api/types'

class MockEventSource {
  public url: string
  public withCredentials?: boolean
  public listeners: Record<string, ((event: any) => void)[]> = {}
  public onerror: ((error: any) => void) | null = null
  public onopen: (() => void) | null = null
  public closed = false

  constructor(url: string, init?: { withCredentials?: boolean }) {
    this.url = url
    this.withCredentials = init?.withCredentials
  }

  public addEventListener(type: string, listener: (event: any) => void) {
    if (!this.listeners[type]) {
      this.listeners[type] = []
    }
    this.listeners[type].push(listener)
  }

  public removeEventListener(type: string, listener: (event: any) => void) {
    if (!this.listeners[type]) return
    this.listeners[type] = this.listeners[type].filter((l) => l !== listener)
  }

  public dispatch(type: string, data: any) {
    const list = this.listeners[type] || []
    for (const listener of list) {
      listener({ data: typeof data === 'string' ? data : JSON.stringify(data) })
    }
  }

  public close() {
    this.closed = true
  }
}

describe('Screen 3: Session Workspace View (SessionWorkspaceView.vue)', () => {
  let router: ReturnType<typeof createRouter>
  let originalEventSource: any
  let activeMockEventSource: MockEventSource | null = null

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

  const mockTools: ToolMetadata[] = [
    {
      id: 'dns_lookup',
      name: 'DNS Record Enumeration',
      category: 'DNS',
      executionType: 'THIRD_PARTY_RECON',
      description: 'Queries DNS records',
      inputSchema: {}
    },
    {
      id: 'whois_lookup',
      name: 'WHOIS / RDAP Registration',
      category: 'WHOIS',
      executionType: 'THIRD_PARTY_RECON',
      description: 'Queries WHOIS directories',
      inputSchema: {}
    },
    {
      id: 'tls_info',
      name: 'TLS/SSL Handshake & Cipher Suite',
      category: 'TLS',
      executionType: 'DIRECT_TARGET_PROBE',
      description: 'Probes TLS configuration',
      inputSchema: {}
    },
    {
      id: 'http_headers',
      name: 'HTTP Headers & Cookies',
      category: 'HTTP',
      executionType: 'DIRECT_TARGET_PROBE',
      description: 'Fetches HTTP response headers',
      inputSchema: {}
    },
    {
      id: 'security_headers_score',
      name: 'Security Headers Evaluation Score',
      category: 'ANALYSIS',
      executionType: 'OFFLINE_ANALYSIS',
      description: 'Offline score evaluation',
      inputSchema: { stepId: '' }
    },
    {
      id: 'cve_matcher',
      name: 'Technology CVE & Flaw Matcher',
      category: 'ANALYSIS',
      executionType: 'OFFLINE_ANALYSIS',
      description: 'Matches CVEs offline',
      inputSchema: { stepId: '' }
    }
  ]

  const mockSteps: StepSummaryResponse[] = [
    {
      executionId: 'step-http-1',
      toolId: 'http_headers',
      status: 'COMPLETED',
      durationMs: 140,
      observationCount: 2,
      startedAt: '2026-10-09T01:41:00Z',
      endedAt: '2026-10-09T01:41:01Z'
    },
    {
      executionId: 'step-tls-2',
      toolId: 'tls_info',
      status: 'COMPLETED',
      durationMs: 210,
      observationCount: 1,
      startedAt: '2026-10-09T01:42:00Z',
      endedAt: '2026-10-09T01:42:01Z'
    }
  ]

  const mockHttpStepDetail: StepDetailResponse = {
    executionId: 'step-http-1',
    toolId: 'http_headers',
    status: 'COMPLETED',
    durationMs: 140,
    failureReason: null,
    rawOutput: 'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nSet-Cookie: session=xyz; Secure; HttpOnly',
    parsedData: {
      statusCode: 200,
      httpVersion: 'HTTP/1.1',
      finalUrl: 'https://example.com/',
      serverBanner: 'nginx/1.24.0',
      headers: {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        server: 'nginx/1.24.0'
      },
      cookies: [
        {
          name: 'session',
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
          path: '/',
          domain: 'example.com'
        }
      ],
      redirectChain: ['http://example.com/', 'https://example.com/']
    },
    score: null,
    observations: [
      {
        id: 'obs-1',
        category: 'SECURITY_HEADERS',
        description: 'Missing Content-Security-Policy header',
        severityHeuristic: 'MEDIUM',
        detectedAt: '2026-10-09T01:41:01Z'
      },
      {
        id: 'obs-2',
        category: 'SECURITY_HEADERS',
        description: 'Missing X-Frame-Options header',
        severityHeuristic: 'LOW',
        detectedAt: '2026-10-09T01:41:01Z'
      }
    ],
    startedAt: '2026-10-09T01:41:00Z',
    endedAt: '2026-10-09T01:41:01Z'
  }

  const mockTlsStepDetail: StepDetailResponse = {
    executionId: 'step-tls-2',
    toolId: 'tls_info',
    status: 'COMPLETED',
    durationMs: 210,
    failureReason: null,
    rawOutput: 'TLS 1.3 / TLS_AES_256_GCM_SHA384',
    parsedData: {
      protocol: 'TLSv1.3',
      cipherSuite: 'TLS_AES_256_GCM_SHA384',
      subject: 'CN=example.com, O=Example Inc',
      issuer: 'CN=DigiCert Global Root CA',
      serialNumber: '04a12b3c4d5e',
      sigAlgName: 'SHA256withRSA',
      notBefore: '2026-01-01T00:00:00Z',
      notAfter: '2027-01-01T00:00:00Z',
      daysUntilExpiry: 90,
      selfSigned: false,
      hostnameVerified: true,
      trustVerified: true,
      sanEntries: ['example.com', 'www.example.com']
    },
    score: null,
    observations: [
      {
        id: 'obs-tls-1',
        category: 'TLS',
        description: 'TLS 1.3 cipher suite verified',
        severityHeuristic: 'INFO',
        detectedAt: '2026-10-09T01:42:01Z'
      }
    ],
    startedAt: '2026-10-09T01:42:00Z',
    endedAt: '2026-10-09T01:42:01Z'
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

    originalEventSource = globalThis.EventSource
    globalThis.EventSource = class extends MockEventSource {
      constructor(url: string, init?: any) {
        super(url, init)
        activeMockEventSource = this
      }
    } as any

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
      if (url.includes('/sessions/test-session-123/steps/step-http-1')) {
        return { data: mockHttpStepDetail } as any
      }
      if (url.includes('/sessions/test-session-123/steps/step-tls-2')) {
        return { data: mockTlsStepDetail } as any
      }
      if (url.includes('/sessions/test-session-123/steps')) {
        return { data: mockSteps } as any
      }
      if (url.includes('/tools')) {
        return { data: mockTools } as any
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
    globalThis.EventSource = originalEventSource
    activeMockEventSource = null
    vi.restoreAllMocks()
  })

  async function createWrapper(sessionId = 'test-session-123') {
    await router.push(`/sessions/${sessionId}`)
    await router.isReady()
    const wrapper = mount(SessionWorkspaceView, {
      global: {
        plugins: [router]
      }
    })
    await flushPromises()
    return wrapper
  }

  // --- Baseline Phase 8 Test Suite Compatibility ---

  it('loads session on mount and renders target URL, mode badge, and state badge', async () => {
    const wrapper = await createWrapper()

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

    await wrapper.find('[data-testid="abort-session-button"]').trigger('click')
    expect(abortSpy).toHaveBeenCalledWith('test-session-123')
  })

  it('navigates back to home when Back button is clicked', async () => {
    const pushSpy = vi.spyOn(router, 'push')
    const wrapper = await createWrapper()

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

    await wrapper.find('[data-testid="complete-session-button"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-testid="workspace-target-url"]').exists()).toBe(true)
    const actionError = wrapper.find('[data-testid="workspace-action-error"]')
    expect(actionError.exists()).toBe(true)
    expect(actionError.text()).toContain('Session Conflict')
    expect(actionError.text()).toContain('Cannot complete session while 1 executions are PENDING or RUNNING')

    await wrapper.find('[data-testid="dismiss-action-error-button"]').trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.find('[data-testid="workspace-action-error"]').exists()).toBe(false)
  })

  it('clears currentSession and renders workspace-error-card when navigating from valid session to 404 session', async () => {
    const store = useSessionsStore()
    const wrapper = await createWrapper('test-session-123')

    expect(wrapper.find('[data-testid="workspace-target-url"]').text()).toBe('https://example.com')
    expect(store.currentSession).not.toBeNull()

    await router.push('/sessions/non-existent-id')
    await flushPromises()

    expect(store.currentSession).toBeNull()
    expect(wrapper.find('[data-testid="workspace-error-card"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('Session Not Found')
  })

  // --- Phase 11 4-Panel Workspace, Tool Catalog & Inspector Tests ---

  it('renders tool catalog across 3 tiers and triggers tool execution on run button click', async () => {
    const wrapper = await createWrapper()

    expect(wrapper.find('[data-testid="tool-card-dns_lookup"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="tool-card-http_headers"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="tool-card-security_headers_score"]').exists()).toBe(true)

    const workspaceStore = useWorkspaceStore()
    const runSpy = vi.spyOn(workspaceStore, 'runTool').mockResolvedValue({
      executionId: 'new-run-123',
      sessionId: 'test-session-123',
      toolId: 'http_headers',
      status: 'PENDING',
      enqueuedAt: '2026-10-09T01:45:00Z'
    })

    await wrapper.find('[data-testid="run-tool-http_headers"]').trigger('click')
    expect(runSpy).toHaveBeenCalledWith('test-session-123', 'http_headers')
  })

  it('disables tool buttons and complete session button when an execution is PENDING or RUNNING', async () => {
    const wrapper = await createWrapper()
    const workspaceStore = useWorkspaceStore()

    // Add a running step
    workspaceStore.steps = [
      {
        executionId: 'active-step-id',
        toolId: 'http_headers',
        status: 'RUNNING',
        durationMs: null,
        observationCount: 0,
        startedAt: '2026-10-09T01:43:00Z',
        endedAt: null
      }
    ]
    await wrapper.vm.$nextTick()

    expect(workspaceStore.hasActiveExecution).toBe(true)
    const runBtn = wrapper.find('[data-testid="run-tool-http_headers"]')
    expect(runBtn.attributes('disabled')).toBeDefined()

    const completeBtn = wrapper.find('[data-testid="complete-session-button"]')
    expect(completeBtn.attributes('disabled')).toBeDefined()
  })

  it('disables offline tools when prerequisite step is not completed and displays hint', async () => {
    const wrapper = await createWrapper()
    const workspaceStore = useWorkspaceStore()

    // Clear steps so no http_headers or tech_detect have run
    workspaceStore.steps = []
    workspaceStore.activeStepDetail = null
    await wrapper.vm.$nextTick()

    const offlineBtn = wrapper.find('[data-testid="run-tool-security_headers_score"]')
    expect(offlineBtn.attributes('disabled')).toBeDefined()

    const offlineCard = wrapper.find('[data-testid="tool-card-security_headers_score"]')
    expect(offlineCard.text()).toContain('Requires completed http_headers step')
  })

  it('switches step selection on timeline click and toggles Parsed View vs Raw Output tabs', async () => {
    const wrapper = await createWrapper()
    const workspaceStore = useWorkspaceStore()

    // Select http_headers step
    await wrapper.find('[data-testid="step-tab-step-http-1"]').trigger('click')
    await flushPromises()

    expect(workspaceStore.activeStepId).toBe('step-http-1')
    expect(wrapper.find('[data-testid="tab-parsed-view"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="parsed-view-content"]').exists()).toBe(true)

    // Switch to Raw Output tab
    await wrapper.find('[data-testid="tab-raw-output"]').trigger('click')
    await wrapper.vm.$nextTick()

    const rawBlock = wrapper.find('[data-testid="raw-output-content"]')
    expect(rawBlock.exists()).toBe(true)
    expect(rawBlock.text()).toContain('Server: nginx/1.24.0')
  })

  it('renders specialized http_headers inspector: headers table, cookies table, and redirect chain', async () => {
    const wrapper = await createWrapper()

    await wrapper.find('[data-testid="step-tab-step-http-1"]').trigger('click')
    await flushPromises()

    // Headers table
    const headersTable = wrapper.find('[data-testid="http-headers-table"]')
    expect(headersTable.exists()).toBe(true)
    expect(headersTable.text()).toContain('strict-transport-security')
    expect(headersTable.text()).toContain('max-age=31536000; includeSubDomains')

    // Cookies table
    const cookiesTable = wrapper.find('[data-testid="http-cookies-table"]')
    expect(cookiesTable.exists()).toBe(true)
    expect(cookiesTable.text()).toContain('session')
    expect(cookiesTable.text()).toContain('example.com')

    // Redirect chain
    const redirectChain = wrapper.find('[data-testid="http-redirect-chain"]')
    expect(redirectChain.exists()).toBe(true)
    expect(redirectChain.text()).toContain('http://example.com/')
    expect(redirectChain.text()).toContain('https://example.com/')

    // Observations list
    const obsList = wrapper.find('[data-testid="step-observations-list"]')
    expect(obsList.exists()).toBe(true)
    expect(obsList.text()).toContain('Missing Content-Security-Policy header')
    expect(obsList.text()).toContain('MEDIUM')
  })

  it('renders specialized tls_info inspector: protocol, cipherSuite, validity, SAN entries, and trust badges', async () => {
    const wrapper = await createWrapper()

    await wrapper.find('[data-testid="step-tab-step-tls-2"]').trigger('click')
    await flushPromises()

    const tlsSummary = wrapper.find('[data-testid="tls-info-summary"]')
    expect(tlsSummary.exists()).toBe(true)
    expect(tlsSummary.text()).toContain('TLSv1.3')
    expect(tlsSummary.text()).toContain('TLS_AES_256_GCM_SHA384')
    expect(tlsSummary.text()).toContain('90 days')
    expect(tlsSummary.text()).toContain('CN=example.com, O=Example Inc')
    expect(tlsSummary.text()).toContain('CN=DigiCert Global Root CA')
    expect(tlsSummary.text()).toContain('CA Trust: Verified')
    expect(tlsSummary.text()).toContain('Hostname: RFC 9525 Verified')
    expect(tlsSummary.text()).toContain('example.com')
    expect(tlsSummary.text()).toContain('www.example.com')
  })

  it('strict XSS prevention: untrusted strings in headers, rawOutput, and SSE messages render purely as text', async () => {
    const wrapper = await createWrapper()
    const workspaceStore = useWorkspaceStore()

    const maliciousString = '<script id="xss-payload">alert("xss")</script><img src="x" onerror="alert(1)">'

    workspaceStore.activeStepDetail = {
      executionId: 'step-xss',
      toolId: 'http_headers',
      status: 'COMPLETED',
      durationMs: 100,
      failureReason: null,
      rawOutput: maliciousString,
      parsedData: {
        statusCode: 200,
        headers: {
          'x-malicious-header': maliciousString
        },
        cookies: [
          {
            name: maliciousString,
            secure: true,
            httpOnly: true,
            sameSite: null,
            path: null,
            domain: null
          }
        ]
      },
      score: null,
      observations: [
        {
          id: 'obs-xss',
          category: 'XSS_TEST',
          description: maliciousString,
          severityHeuristic: 'HIGH',
          detectedAt: '2026-10-09T01:45:00Z'
        }
      ],
      startedAt: null,
      endedAt: null
    }

    workspaceStore.appendSseEvent('test_xss', 'INFO', maliciousString, {})
    await wrapper.vm.$nextTick()

    // Query DOM: verify script tag was NOT injected into the document
    expect(wrapper.find('#xss-payload').exists()).toBe(false)
    expect(wrapper.html()).not.toContain('<script id="xss-payload">')
    expect(wrapper.text()).toContain('<script id="xss-payload">alert("xss")</script>')
  })

  it('renders bottom Live SSE Panel: status badge, level filtering, clear, collapse, and deterministic close on unmount', async () => {
    const wrapper = await createWrapper()
    const workspaceStore = useWorkspaceStore()

    expect(activeMockEventSource).not.toBeNull()
    expect(activeMockEventSource!.closed).toBe(false)

    // Dispatch connected event
    activeMockEventSource!.dispatch('connected', { sessionId: 'test-session-123' })
    await wrapper.vm.$nextTick()

    const statusBadge = wrapper.find('[data-testid="sse-status-badge"]')
    expect(statusBadge.text()).toBe('CONNECTED')

    // Append multiple levels
    workspaceStore.appendSseEvent('test_info', 'INFO', 'Info message', {})
    workspaceStore.appendSseEvent('test_warn', 'WARN', 'Warning message', {})
    workspaceStore.appendSseEvent('test_error', 'ERROR', 'Error message', {})
    await wrapper.vm.$nextTick()

    let eventItems = wrapper.findAll('[data-testid="sse-event-item"]')
    expect(eventItems.length).toBeGreaterThanOrEqual(3)

    // Filter by ERROR
    const filterSelect = wrapper.find('[data-testid="sse-level-filter"]')
    await filterSelect.setValue('ERROR')
    await wrapper.vm.$nextTick()

    eventItems = wrapper.findAll('[data-testid="sse-event-item"]')
    expect(eventItems).toHaveLength(1)
    expect(eventItems[0].text()).toContain('Error message')

    // Clear events
    await wrapper.find('[data-testid="sse-clear-button"]').trigger('click')
    await wrapper.vm.$nextTick()
    expect(workspaceStore.sseEvents).toHaveLength(0)

    // Collapse toggle
    const collapseBtn = wrapper.find('[data-testid="sse-collapse-toggle"]')
    expect(wrapper.find('[data-testid="sse-event-list"]').exists()).toBe(true)

    await collapseBtn.trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.find('[data-testid="sse-event-list"]').exists()).toBe(false)

    // Deterministic unmount cleanup
    wrapper.unmount()
    expect(activeMockEventSource!.closed).toBe(true)
    expect(workspaceStore.sseConnectionState).toBe('DISCONNECTED')
  })

  it('renders structured redirect objects in http_headers redirect chain', async () => {
    const wrapper = await createWrapper()
    const workspaceStore = useWorkspaceStore()

    workspaceStore.activeStepDetail = {
      executionId: 'step-redirect-structured',
      toolId: 'http_headers',
      status: 'COMPLETED',
      durationMs: 120,
      failureReason: null,
      rawOutput: 'HTTP/1.1 200 OK',
      parsedData: {
        statusCode: 200,
        headers: {},
        cookies: [],
        redirectChain: [
          {
            hop: 1,
            fromUrl: 'http://example.com/',
            toUrl: 'https://example.com/',
            statusCode: 301
          }
        ]
      },
      score: null,
      observations: [],
      startedAt: null,
      endedAt: null
    }
    await wrapper.vm.$nextTick()

    const redirectChain = wrapper.find('[data-testid="http-redirect-chain"]')
    expect(redirectChain.exists()).toBe(true)
    expect(redirectChain.text()).toContain('Hop 1 (HTTP 301): http://example.com/ -> https://example.com/')
  })

  it('renders inspector-step-running when a step is PENDING even if activeStepDetail is null', async () => {
    const wrapper = await createWrapper()
    const workspaceStore = useWorkspaceStore()

    workspaceStore.steps = [
      {
        executionId: 'step-pending-only',
        toolId: 'http_headers',
        status: 'PENDING',
        durationMs: null,
        observationCount: 0,
        startedAt: null,
        endedAt: null
      }
    ]
    workspaceStore.activeStepId = 'step-pending-only'
    workspaceStore.activeStepDetail = null
    await wrapper.vm.$nextTick()

    const runningIndicator = wrapper.find('[data-testid="inspector-step-running"]')
    expect(runningIndicator.exists()).toBe(true)
    expect(runningIndicator.text()).toContain('Executing probe http_headers...')
  })

  it('does not call connectSse if component is unmounted while fetchSessionById is pending', async () => {
    let resolveSession: (val: any) => void = () => {}
    const sessionPromise = new Promise((resolve) => {
      resolveSession = resolve
    })

    vi.spyOn(http, 'get').mockImplementation((url: string) => {
      if (url.includes('/sessions/test-session-unmount')) {
        return sessionPromise as any
      }
      return Promise.resolve({ data: {} }) as any
    })

    const workspaceStore = useWorkspaceStore()
    const connectSpy = vi.spyOn(workspaceStore, 'connectSse')

    await router.push('/sessions/test-session-unmount')
    await router.isReady()
    const wrapper = mount(SessionWorkspaceView, {
      global: {
        plugins: [router]
      }
    })

    // Unmount before sessionPromise resolves
    wrapper.unmount()

    // Now resolve fetchSessionById
    resolveSession({ data: { ...mockSession, id: 'test-session-unmount' } })
    await flushPromises()

    // connectSse MUST NOT have been called
    expect(connectSpy).not.toHaveBeenCalledWith('test-session-unmount')
  })
})
