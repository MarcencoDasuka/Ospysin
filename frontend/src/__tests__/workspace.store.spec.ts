import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useWorkspaceStore } from '@/stores/workspace'
import { useSessionsStore } from '@/stores/sessions'
import { http } from '@/api/http'
import type {
  ToolMetadata,
  StepSummaryResponse,
  StepDetailResponse,
  ToolRunAcceptedResponse,
  AuditSession
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

describe('Workspace Store (useWorkspaceStore)', () => {
  let originalEventSource: any

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
      id: 'http_headers',
      name: 'HTTP Headers & Cookies',
      category: 'HTTP',
      executionType: 'DIRECT_TARGET_PROBE',
      description: 'Probes HTTP headers',
      inputSchema: {}
    },
    {
      id: 'security_headers_score',
      name: 'Security Headers Evaluation Score',
      category: 'ANALYSIS',
      executionType: 'OFFLINE_ANALYSIS',
      description: 'Calculates security score offline',
      inputSchema: { stepId: '' }
    }
  ]

  const mockSession: AuditSession = {
    id: 'session-123',
    targetUrl: 'https://example.com',
    mode: 'PUBLIC',
    state: 'ACTIVE',
    scopeAcknowledged: true,
    scopeAckVersion: '1.0.0',
    scopeAckHash: 'hash-abc',
    scopeAckTimestamp: '2026-10-09T01:40:00Z',
    stepCount: 1,
    findingCount: 0,
    createdAt: '2026-10-09T01:40:00Z',
    updatedAt: '2026-10-09T01:40:00Z'
  }

  beforeEach(() => {
    setActivePinia(createPinia())
    originalEventSource = globalThis.EventSource
    globalThis.EventSource = MockEventSource as any
  })

  afterEach(() => {
    globalThis.EventSource = originalEventSource
    vi.restoreAllMocks()
  })

  it('fetchTools retrieves tools and groups them into toolsByTier in canonical order', async () => {
    vi.spyOn(http, 'get').mockResolvedValueOnce({ data: mockTools } as any)

    const store = useWorkspaceStore()
    const result = await store.fetchTools()

    expect(result).toHaveLength(3)
    expect(store.tools).toHaveLength(3)

    const tiers = store.toolsByTier
    expect(tiers).toHaveLength(3)
    expect(tiers[0].tier).toBe('THIRD_PARTY_RECON')
    expect(tiers[0].label).toBe('External Third-Party Recon')
    expect(tiers[0].tools).toHaveLength(1)
    expect(tiers[0].tools[0].id).toBe('dns_lookup')

    expect(tiers[1].tier).toBe('DIRECT_TARGET_PROBE')
    expect(tiers[1].label).toBe('Active Direct Target Probes')
    expect(tiers[1].tools).toHaveLength(1)
    expect(tiers[1].tools[0].id).toBe('http_headers')

    expect(tiers[2].tier).toBe('OFFLINE_ANALYSIS')
    expect(tiers[2].label).toBe('Offline Analytical')
    expect(tiers[2].tools).toHaveLength(1)
    expect(tiers[2].tools[0].id).toBe('security_headers_score')
  })

  it('fetchSteps loads chronological steps and auto-selects the latest step if none selected', async () => {
    const mockSteps: StepSummaryResponse[] = [
      {
        executionId: 'step-1',
        toolId: 'dns_lookup',
        status: 'COMPLETED',
        durationMs: 150,
        observationCount: 0,
        startedAt: '2026-10-09T01:41:00Z',
        endedAt: '2026-10-09T01:41:01Z'
      },
      {
        executionId: 'step-2',
        toolId: 'http_headers',
        status: 'COMPLETED',
        durationMs: 220,
        observationCount: 2,
        startedAt: '2026-10-09T01:42:00Z',
        endedAt: '2026-10-09T01:42:01Z'
      }
    ]

    const mockDetail: StepDetailResponse = {
      executionId: 'step-2',
      toolId: 'http_headers',
      status: 'COMPLETED',
      durationMs: 220,
      failureReason: null,
      rawOutput: 'HTTP/1.1 200 OK',
      parsedData: { statusCode: 200 },
      score: null,
      observations: [],
      startedAt: '2026-10-09T01:42:00Z',
      endedAt: '2026-10-09T01:42:01Z'
    }

    vi.spyOn(http, 'get').mockImplementation(async (url: string) => {
      if (url.includes('/steps/step-2')) {
        return { data: mockDetail } as any
      }
      if (url.includes('/steps')) {
        return { data: mockSteps } as any
      }
      throw new Error(`Unexpected url: ${url}`)
    })

    const store = useWorkspaceStore()
    expect(store.activeStepId).toBeNull()

    await store.fetchSteps('session-123')

    expect(store.steps).toHaveLength(2)
    expect(store.activeStepId).toBe('step-2')
    expect(store.activeStepDetail?.executionId).toBe('step-2')
  })

  it('prevents race conditions when rapidly switching steps: slow response does not overwrite newer selected step', async () => {
    const store = useWorkspaceStore()

    let resolveStep1: (val: any) => void = () => {}
    let resolveStep2: (val: any) => void = () => {}

    const promise1 = new Promise((resolve) => {
      resolveStep1 = resolve
    })
    const promise2 = new Promise((resolve) => {
      resolveStep2 = resolve
    })

    vi.spyOn(http, 'get').mockImplementation((url: string) => {
      if (url.includes('/steps/step-1')) {
        return promise1 as any
      }
      if (url.includes('/steps/step-2')) {
        return promise2 as any
      }
      throw new Error(`Unexpected url: ${url}`)
    })

    // Operator clicks step-1, then immediately clicks step-2
    const fetch1 = store.selectStep('session-123', 'step-1')
    expect(store.activeStepId).toBe('step-1')

    const fetch2 = store.selectStep('session-123', 'step-2')
    expect(store.activeStepId).toBe('step-2')

    // Faster step-2 completes first
    resolveStep2({
      data: {
        executionId: 'step-2',
        toolId: 'http_headers',
        status: 'COMPLETED',
        durationMs: 100,
        failureReason: null,
        rawOutput: 'step 2 output',
        parsedData: {},
        score: null,
        observations: [],
        startedAt: null,
        endedAt: null
      }
    })
    await fetch2

    expect(store.activeStepDetail?.executionId).toBe('step-2')
    expect(store.activeStepDetail?.rawOutput).toBe('step 2 output')

    // Slower step-1 completes later — must be ignored due to seq check & activeStepId guard
    resolveStep1({
      data: {
        executionId: 'step-1',
        toolId: 'dns_lookup',
        status: 'COMPLETED',
        durationMs: 500,
        failureReason: null,
        rawOutput: 'slow step 1 output',
        parsedData: {},
        score: null,
        observations: [],
        startedAt: null,
        endedAt: null
      }
    })
    await fetch1

    // State MUST STILL be step-2, NOT overwritten by step-1
    expect(store.activeStepId).toBe('step-2')
    expect(store.activeStepDetail?.executionId).toBe('step-2')
    expect(store.activeStepDetail?.rawOutput).toBe('step 2 output')
  })

  it('runTool triggers probe, optimistically appends step, and auto-populates stepId for offline tools', async () => {
    const sessionsStore = useSessionsStore()
    sessionsStore.currentSession = { ...mockSession }

    const store = useWorkspaceStore()
    // Populate existing step for http_headers completed
    store.steps = [
      {
        executionId: 'existing-http-step-id',
        toolId: 'http_headers',
        status: 'COMPLETED',
        durationMs: 120,
        observationCount: 1,
        startedAt: '2026-10-09T01:40:00Z',
        endedAt: '2026-10-09T01:40:01Z'
      }
    ]

    let postedUrl = ''
    let postedBody: any = null

    vi.spyOn(http, 'post').mockImplementation(async (url: string, body: any) => {
      postedUrl = url
      postedBody = body
      const accepted: ToolRunAcceptedResponse = {
        executionId: 'new-offline-step-id',
        sessionId: 'session-123',
        toolId: 'security_headers_score',
        status: 'PENDING',
        enqueuedAt: '2026-10-09T01:45:00Z'
      }
      return { data: accepted } as any
    })

    const accepted = await store.runTool('session-123', 'security_headers_score')

    expect(postedUrl).toBe('/sessions/session-123/tools/security_headers_score/run')
    expect(postedBody).toEqual({ stepId: 'existing-http-step-id' })
    expect(accepted.executionId).toBe('new-offline-step-id')
    expect(store.activeStepId).toBe('new-offline-step-id')
    expect(store.steps.some((s) => s.executionId === 'new-offline-step-id')).toBe(true)
    expect(sessionsStore.currentSession?.stepCount).toBe(2)
  })

  it('runTool immediately sets activeStepDetail to a PENDING snapshot even when an older COMPLETED step was selected', async () => {
    const sessionsStore = useSessionsStore()
    sessionsStore.currentSession = { ...mockSession }

    const store = useWorkspaceStore()
    store.activeStepId = 'old-step-1'
    store.activeStepDetail = {
      executionId: 'old-step-1',
      toolId: 'dns_lookup',
      status: 'COMPLETED',
      durationMs: 150,
      failureReason: null,
      rawOutput: 'dns result',
      parsedData: { records: {} },
      score: null,
      observations: [],
      startedAt: '2026-10-09T01:40:00Z',
      endedAt: '2026-10-09T01:40:01Z'
    }

    vi.spyOn(http, 'post').mockResolvedValueOnce({
      data: {
        executionId: 'new-probe-step-2',
        sessionId: 'session-123',
        toolId: 'http_headers',
        status: 'PENDING',
        enqueuedAt: '2026-10-09T01:45:00Z'
      }
    } as any)

    await store.runTool('session-123', 'http_headers')

    expect(store.activeStepId).toBe('new-probe-step-2')
    expect(store.activeStepDetail).not.toBeNull()
    expect(store.activeStepDetail?.executionId).toBe('new-probe-step-2')
    expect(store.activeStepDetail?.toolId).toBe('http_headers')
    expect(store.activeStepDetail?.status).toBe('PENDING')
    expect(store.activeStepDetail?.rawOutput).toBeNull()
    expect(store.activeStepDetail?.parsedData).toEqual({})
  })

  it('runTool prevents duplicate concurrent execution triggers while in flight', async () => {
    const store = useWorkspaceStore()
    store.triggeringToolId = 'http_headers'

    await expect(store.runTool('session-123', 'tls_info')).rejects.toThrow(
      'A tool execution is already in flight'
    )
  })

  it('SSE lifecycle: connects, receives lifecycle events, caps buffer at 500, and disconnects deterministically', async () => {
    let activeInstance: MockEventSource | null = null

    class RecordingMockEventSource extends MockEventSource {
      constructor(url: string, init?: any) {
        super(url, init)
        activeInstance = this
      }
    }
    globalThis.EventSource = RecordingMockEventSource as any

    const sessionsStore = useSessionsStore()
    sessionsStore.currentSession = { ...mockSession, state: 'ACTIVE' }

    const store = useWorkspaceStore()
    store.connectSse('session-123')

    expect(activeInstance).not.toBeNull()
    expect(activeInstance!.closed).toBe(false)
    expect(activeInstance!.url).toBe('/api/sessions/session-123/events')
    expect(activeInstance!.withCredentials).toBe(true)

    // 1. Connected
    activeInstance!.dispatch('connected', { sessionId: 'session-123' })
    expect(store.sseConnectionState).toBe('CONNECTED')
    expect(store.sseEvents).toHaveLength(1)
    expect(store.sseEvents[0].level).toBe('INFO')

    // 2. step_queued
    activeInstance!.dispatch('step_queued', {
      executionId: 'step-sse-1',
      toolId: 'http_headers',
      status: 'PENDING'
    })
    expect(store.steps.some((s) => s.executionId === 'step-sse-1')).toBe(true)
    expect(store.activeStepId).toBe('step-sse-1')

    // 3. step_started
    activeInstance!.dispatch('step_started', {
      executionId: 'step-sse-1',
      toolId: 'http_headers',
      status: 'RUNNING',
      startedAt: '2026-10-09T01:46:00Z'
    })
    const startedStep = store.steps.find((s) => s.executionId === 'step-sse-1')
    expect(startedStep?.status).toBe('RUNNING')

    // 4. step_finished
    vi.spyOn(http, 'get').mockResolvedValue({
      data: {
        executionId: 'step-sse-1',
        toolId: 'http_headers',
        status: 'COMPLETED',
        durationMs: 250,
        failureReason: null,
        rawOutput: 'RAW',
        parsedData: {},
        score: null,
        observations: [],
        startedAt: '2026-10-09T01:46:00Z',
        endedAt: '2026-10-09T01:46:01Z'
      }
    } as any)

    activeInstance!.dispatch('step_finished', {
      executionId: 'step-sse-1',
      toolId: 'http_headers',
      durationMs: 250,
      observationCount: 1
    })
    const finishedStep = store.steps.find((s) => s.executionId === 'step-sse-1')
    expect(finishedStep?.status).toBe('COMPLETED')
    expect(finishedStep?.durationMs).toBe(250)

    // 5. policy_alert
    activeInstance!.dispatch('policy_alert', {
      level: 'WARN',
      message: 'Private IP access prohibited'
    })
    expect(store.policyAlertMessage).toBe('Private IP access prohibited')

    // 6. Buffer cap: flood 600 events
    for (let i = 0; i < 600; i++) {
      store.appendSseEvent('test_event', 'INFO', `Message ${i}`, {})
    }
    expect(store.sseEvents.length).toBe(500)
    expect(store.sseEvents[499].message).toBe('Message 599')

    // 7. session_completed
    activeInstance!.dispatch('session_completed', { sessionId: 'session-123' })
    expect(sessionsStore.currentSession.state).toBe('COMPLETED')

    // 8. session_aborted
    sessionsStore.currentSession.state = 'ACTIVE'
    store.steps = [
      {
        executionId: 'pending-step',
        toolId: 'robots_txt',
        status: 'PENDING',
        durationMs: null,
        observationCount: 0,
        startedAt: null,
        endedAt: null
      }
    ]
    activeInstance!.dispatch('session_aborted', { sessionId: 'session-123' })
    expect(sessionsStore.currentSession.state).toBe('ABORTED')
    expect(store.steps[0].status).toBe('CANCELLED')

    // 9. Deterministic disconnect
    store.disconnectSse()
    expect(activeInstance!.closed).toBe(true)
    expect(store.sseConnectionState).toBe('DISCONNECTED')
  })

  it('requestStepComment calls backend endpoint and handles requestingComment lifecycle', async () => {
    const store = useWorkspaceStore()
    expect(store.requestingComment).toBe(false)

    let postedUrl = ''
    let postedBody: any = null
    vi.spyOn(http, 'post').mockImplementation(async (url: string, body: any) => {
      postedUrl = url
      postedBody = body
      return { data: { status: 'PENDING', message: 'LLM commentary request enqueued' } } as any
    })

    const result = await store.requestStepComment('session-123', 'step-abc')

    expect(postedUrl).toBe('/sessions/session-123/llm/comment')
    expect(postedBody).toEqual({ stepId: 'step-abc' })
    expect(result.status).toBe('PENDING')
    expect(store.requestingComment).toBe(true)
  })

  it('sendChatMessage appends user message, calls backend endpoint and handles sendingChat lifecycle', async () => {
    const store = useWorkspaceStore()
    expect(store.chatMessages).toHaveLength(0)
    expect(store.sendingChat).toBe(false)

    let postedUrl = ''
    let postedBody: any = null
    vi.spyOn(http, 'post').mockImplementation(async (url: string, body: any) => {
      postedUrl = url
      postedBody = body
      return { data: { status: 'PENDING', message: 'Chat query enqueued' } } as any
    })

    const result = await store.sendChatMessage('session-123', 'Why is HSTS important?')

    expect(postedUrl).toBe('/sessions/session-123/llm/chat')
    expect(postedBody).toEqual({ message: 'Why is HSTS important?' })
    expect(result.status).toBe('PENDING')
    expect(store.chatMessages).toHaveLength(1)
    expect(store.chatMessages[0].role).toBe('user')
    expect(store.chatMessages[0].content).toBe('Why is HSTS important?')
    expect(store.sendingChat).toBe(true)

    // Rejects blank message
    await expect(store.sendChatMessage('session-123', '   ')).rejects.toThrow(
      'Chat message cannot be blank'
    )
  })

  it('SSE handles llm_comment_ready and llm_chat_reply and resetWorkspace clears LLM state', () => {
    let activeInstance: MockEventSource | null = null
    class RecordingMockEventSource extends MockEventSource {
      constructor(url: string, init?: any) {
        super(url, init)
        activeInstance = this
      }
    }
    globalThis.EventSource = RecordingMockEventSource as any

    const store = useWorkspaceStore()
    store.connectSse('session-123')
    store.requestingComment = true
    store.sendingChat = true

    // 1. Dispatch llm_comment_ready
    activeInstance!.dispatch('llm_comment_ready', {
      stepId: 'step-1',
      toolId: 'http_headers',
      comment: 'Missing CSP header detected.',
      suggestedTool: 'tls_info',
      suggestedReason: 'Inspect TLS certificate.',
      timestamp: '2026-10-15T12:00:00Z'
    })

    expect(store.latestAdvisory).not.toBeNull()
    expect(store.latestAdvisory?.comment).toBe('Missing CSP header detected.')
    expect(store.latestAdvisory?.suggestedTool).toBe('tls_info')
    expect(store.latestAdvisory?.suggestedReason).toBe('Inspect TLS certificate.')
    expect(store.requestingComment).toBe(false)

    // 2. Dispatch llm_chat_reply
    activeInstance!.dispatch('llm_chat_reply', {
      reply: 'HSTS ensures browsers only connect via HTTPS.'
    })

    expect(store.chatMessages).toHaveLength(1)
    expect(store.chatMessages[0].role).toBe('assistant')
    expect(store.chatMessages[0].content).toBe('HSTS ensures browsers only connect via HTTPS.')
    expect(store.sendingChat).toBe(false)

    // 3. resetWorkspace clears all LLM state
    store.resetWorkspace()
    expect(store.latestAdvisory).toBeNull()
    expect(store.chatMessages).toHaveLength(0)
    expect(store.requestingComment).toBe(false)
    expect(store.sendingChat).toBe(false)
  })

  it('SSE resets requestingComment and sendingChat on session_completed, session_aborted, and onerror (P12-05)', () => {
    let activeInstance: MockEventSource | null = null
    class RecordingMockEventSource extends MockEventSource {
      constructor(url: string, init?: any) {
        super(url, init)
        activeInstance = this
      }
    }
    globalThis.EventSource = RecordingMockEventSource as any

    const store = useWorkspaceStore()
    store.connectSse('session-123')

    // 1. Reset on session_completed
    store.requestingComment = true
    store.sendingChat = true
    activeInstance!.dispatch('session_completed', { sessionId: 'session-123' })
    expect(store.requestingComment).toBe(false)
    expect(store.sendingChat).toBe(false)

    // 2. Reset on session_aborted
    store.requestingComment = true
    store.sendingChat = true
    activeInstance!.dispatch('session_aborted', { sessionId: 'session-123' })
    expect(store.requestingComment).toBe(false)
    expect(store.sendingChat).toBe(false)

    // 3. Reset on onerror
    store.requestingComment = true
    store.sendingChat = true
    activeInstance!.onerror?.(new Event('error'))
    expect(store.sseConnectionState).toBe('ERROR')
    expect(store.requestingComment).toBe(false)
    expect(store.sendingChat).toBe(false)
  })

  describe('Phase 17: Findings Curation & Report Actions', () => {
    it('fetchFindings retrieves session findings and populates findings state', async () => {
      const mockFindings = [
        {
          id: 'f-1',
          sessionId: 'session-123',
          observationId: null,
          title: 'Missing CSP',
          description: 'No Content-Security-Policy header',
          severity: 'MEDIUM',
          confidence: 'FIRM',
          status: 'OPEN',
          rejectionReason: null,
          remediation: 'Add CSP header',
          evidence: [],
          createdAt: '2026-10-09T01:40:00Z',
          updatedAt: '2026-10-09T01:40:00Z'
        }
      ]

      vi.spyOn(http, 'get').mockResolvedValueOnce({ data: mockFindings } as any)

      const store = useWorkspaceStore()
      const result = await store.fetchFindings('session-123')

      expect(http.get).toHaveBeenCalledWith('/sessions/session-123/findings')
      expect(result).toEqual(mockFindings)
      expect(store.findings).toEqual(mockFindings)
      expect(store.activeFindingsCount).toBe(1)
    })

    it('createFinding appends to findings and syncs sessionsStore.currentSession.findingCount', async () => {
      const sessionsStore = useSessionsStore()
      sessionsStore.currentSession = {
        id: 'session-123',
        targetUrl: 'https://example.com',
        mode: 'PUBLIC',
        state: 'ACTIVE',
        scopeAcknowledged: true,
        scopeAckVersion: '1.0.0',
        scopeAckHash: 'hash',
        scopeAckTimestamp: '2026-10-09T01:40:00Z',
        stepCount: 1,
        findingCount: 0,
        createdAt: '2026-10-09T01:40:00Z',
        updatedAt: '2026-10-09T01:40:00Z'
      }

      const newFinding = {
        id: 'f-2',
        sessionId: 'session-123',
        observationId: 'obs-1',
        title: 'HSTS Not Enforced',
        description: 'Server lacks HSTS header',
        severity: 'HIGH' as const,
        confidence: 'FIRM' as const,
        status: 'OPEN' as const,
        rejectionReason: null,
        remediation: null,
        evidence: [],
        createdAt: '2026-10-09T01:41:00Z',
        updatedAt: '2026-10-09T01:41:00Z'
      }

      vi.spyOn(http, 'post').mockResolvedValueOnce({ data: newFinding } as any)

      const store = useWorkspaceStore()
      const created = await store.createFinding('session-123', {
        observationId: 'obs-1',
        title: 'HSTS Not Enforced',
        description: 'Server lacks HSTS header',
        severity: 'HIGH'
      })

      expect(http.post).toHaveBeenCalledWith('/sessions/session-123/findings', {
        observationId: 'obs-1',
        title: 'HSTS Not Enforced',
        description: 'Server lacks HSTS header',
        severity: 'HIGH'
      })
      expect(created).toEqual(newFinding)
      expect(store.findings).toContainEqual(newFinding)
      expect(sessionsStore.currentSession.findingCount).toBe(1)
    })

    it('updateFinding updates matching finding and recalculates active count on REJECTED', async () => {
      const sessionsStore = useSessionsStore()
      sessionsStore.currentSession = {
        id: 'session-123',
        targetUrl: 'https://example.com',
        mode: 'PUBLIC',
        state: 'ACTIVE',
        scopeAcknowledged: true,
        scopeAckVersion: '1.0.0',
        scopeAckHash: 'hash',
        scopeAckTimestamp: '2026-10-09T01:40:00Z',
        stepCount: 1,
        findingCount: 1,
        createdAt: '2026-10-09T01:40:00Z',
        updatedAt: '2026-10-09T01:40:00Z'
      }

      const store = useWorkspaceStore()
      store.findings = [
        {
          id: 'f-1',
          sessionId: 'session-123',
          observationId: null,
          title: 'Missing CSP',
          description: 'Desc',
          severity: 'MEDIUM',
          confidence: 'FIRM',
          status: 'OPEN',
          rejectionReason: null,
          remediation: null,
          evidence: [],
          createdAt: '2026-10-09T01:40:00Z',
          updatedAt: '2026-10-09T01:40:00Z'
        }
      ]

      const updatedFinding = {
        ...store.findings[0],
        status: 'REJECTED' as const,
        rejectionReason: 'Protected by external WAF'
      }

      vi.spyOn(http, 'patch').mockResolvedValueOnce({ data: updatedFinding } as any)

      await store.updateFinding('session-123', 'f-1', {
        status: 'REJECTED',
        rejectionReason: 'Protected by external WAF'
      })

      expect(http.patch).toHaveBeenCalledWith('/sessions/session-123/findings/f-1', {
        status: 'REJECTED',
        rejectionReason: 'Protected by external WAF'
      })
      expect(store.findings[0].status).toBe('REJECTED')
      expect(store.activeFindingsCount).toBe(0)
      expect(sessionsStore.currentSession.findingCount).toBe(0)
    })

    it('updateFinding transitioning status to FALSE_POSITIVE decrements active findings and session count', async () => {
      const sessionsStore = useSessionsStore()
      sessionsStore.currentSession = {
        id: 'session-123',
        targetUrl: 'https://example.com',
        mode: 'PUBLIC',
        state: 'ACTIVE',
        scopeAcknowledged: true,
        scopeAckVersion: '1.0.0',
        scopeAckHash: 'hash',
        scopeAckTimestamp: '2026-10-09T01:40:00Z',
        stepCount: 1,
        findingCount: 1,
        createdAt: '2026-10-09T01:40:00Z',
        updatedAt: '2026-10-09T01:40:00Z'
      }

      const store = useWorkspaceStore()
      store.findings = [
        {
          id: 'f-1',
          sessionId: 'session-123',
          observationId: null,
          title: 'Missing CSP',
          description: 'Desc',
          severity: 'MEDIUM',
          confidence: 'FIRM',
          status: 'OPEN',
          rejectionReason: null,
          remediation: null,
          evidence: [],
          createdAt: '2026-10-09T01:40:00Z',
          updatedAt: '2026-10-09T01:40:00Z'
        }
      ]

      const updatedFinding = {
        ...store.findings[0],
        status: 'FALSE_POSITIVE' as const
      }

      vi.spyOn(http, 'patch').mockResolvedValueOnce({ data: updatedFinding } as any)

      await store.updateFinding('session-123', 'f-1', {
        status: 'FALSE_POSITIVE'
      })

      expect(http.patch).toHaveBeenCalledWith('/sessions/session-123/findings/f-1', {
        status: 'FALSE_POSITIVE'
      })
      expect(store.findings[0].status).toBe('FALSE_POSITIVE')
      expect(store.activeFindingsCount).toBe(0)
      expect(sessionsStore.currentSession.findingCount).toBe(0)
    })

    it('addEvidence attaches evidence to the matching finding', async () => {
      const store = useWorkspaceStore()
      store.findings = [
        {
          id: 'f-1',
          sessionId: 'session-123',
          observationId: null,
          title: 'Missing CSP',
          description: 'Desc',
          severity: 'MEDIUM',
          confidence: 'FIRM',
          status: 'OPEN',
          rejectionReason: null,
          remediation: null,
          evidence: [],
          createdAt: '2026-10-09T01:40:00Z',
          updatedAt: '2026-10-09T01:40:00Z'
        }
      ]

      const evidenceItem = {
        id: 'ev-1',
        findingId: 'f-1',
        resultId: 'res-1',
        executionId: 'exec-1',
        toolId: 'http_headers',
        snippet: 'Strict-Transport-Security: max-age=0',
        createdAt: '2026-10-09T01:42:00Z'
      }

      vi.spyOn(http, 'post').mockResolvedValueOnce({ data: evidenceItem } as any)

      const result = await store.addEvidence('session-123', 'f-1', {
        resultId: 'res-1',
        snippet: 'Strict-Transport-Security: max-age=0'
      })

      expect(http.post).toHaveBeenCalledWith('/sessions/session-123/findings/f-1/evidence', {
        resultId: 'res-1',
        snippet: 'Strict-Transport-Security: max-age=0'
      })
      expect(result).toEqual(evidenceItem)
      expect(store.findings[0].evidence).toHaveLength(1)
      expect(store.findings[0].evidence[0]).toEqual(evidenceItem)
    })

    it('fetchReportHtml retrieves standalone HTML document as text', async () => {
      const rawHtml = '<!DOCTYPE html><html><body>Report</body></html>'
      vi.spyOn(http, 'get').mockResolvedValueOnce({ data: rawHtml } as any)

      const store = useWorkspaceStore()
      const result = await store.fetchReportHtml('session-123')

      expect(http.get).toHaveBeenCalledWith('/sessions/session-123/report', {
        responseType: 'text'
      })
      expect(result).toBe(rawHtml)
    })
  })
})
