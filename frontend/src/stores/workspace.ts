import { defineStore } from 'pinia'
import { ref, shallowRef, computed } from 'vue'
import { http, ApiError } from '@/api/http'
import { useSessionsStore } from './sessions'
import type {
  ToolMetadata,
  StepSummaryResponse,
  StepDetailResponse,
  WorkspaceSseEvent,
  SseConnectionState,
  SseLogLevel,
  ExecutionType,
  ToolRunAcceptedResponse,
  ProblemDetail,
  LlmCommentPayload,
  LlmChatMessage,
  LlmAsyncAcceptedResponse,
  Finding,
  CreateFindingRequest,
  UpdateFindingRequest,
  CreateEvidenceRequest,
  EvidenceItem
} from '@/api/types'

export interface ToolTierGroup {
  tier: ExecutionType
  label: string
  tools: ToolMetadata[]
}

const TIER_CONFIG: { tier: ExecutionType; label: string }[] = [
  { tier: 'THIRD_PARTY_RECON', label: 'External Third-Party Recon' },
  { tier: 'DIRECT_TARGET_PROBE', label: 'Active Direct Target Probes' },
  { tier: 'OFFLINE_ANALYSIS', label: 'Offline Analytical' }
]

export const useWorkspaceStore = defineStore('workspace', () => {
  // State
  const tools = ref<ToolMetadata[]>([])
  const steps = ref<StepSummaryResponse[]>([])
  const activeStepId = ref<string | null>(null)
  const activeStepDetail = shallowRef<StepDetailResponse | null>(null)
  const sseEvents = shallowRef<WorkspaceSseEvent[]>([])
  const sseConnectionState = ref<SseConnectionState>('DISCONNECTED')
  const policyAlertMessage = ref<string | null>(null)

  // Findings Curation State
  const findings = ref<Finding[]>([])
  const loadingFindings = ref(false)
  const submittingFinding = ref(false)

  // LLM Advisory & Tactical Chat State
  const latestAdvisory = ref<LlmCommentPayload | null>(null)
  const chatMessages = ref<LlmChatMessage[]>([])
  const requestingComment = ref(false)
  const sendingChat = ref(false)

  const loadingTools = ref(false)
  const loadingSteps = ref(false)
  const loadingStepDetail = ref(false)
  const triggeringToolId = ref<string | null>(null)
  const error = ref<ProblemDetail | null>(null)

  // Internal guards & refs
  let detailRequestSeq = 0
  let activeEventSource: EventSource | null = null

  // Getters
  const toolsByTier = computed<ToolTierGroup[]>(() => {
    return TIER_CONFIG.map(({ tier, label }) => ({
      tier,
      label,
      tools: tools.value.filter((t) => t.executionType === tier)
    }))
  })

  const hasActiveExecution = computed<boolean>(() => {
    return steps.value.some((s) => s.status === 'PENDING' || s.status === 'RUNNING')
  })

  const latestCompletedHttpHeadersStepId = computed<string | null>(() => {
    for (let i = steps.value.length - 1; i >= 0; i--) {
      const step = steps.value[i]
      if (step.toolId === 'http_headers' && step.status === 'COMPLETED') {
        return step.executionId
      }
    }
    return null
  })

  const latestCompletedTechDetectStepId = computed<string | null>(() => {
    for (let i = steps.value.length - 1; i >= 0; i--) {
      const step = steps.value[i]
      if (step.toolId === 'tech_detect' && step.status === 'COMPLETED') {
        return step.executionId
      }
    }
    return null
  })

  const activeFindingsCount = computed<number>(() => {
    return Array.isArray(findings.value)
      ? findings.value.filter((f) => f.status !== 'REJECTED' && f.status !== 'FALSE_POSITIVE').length
      : 0
  })

  // SSE Helper with 500 max event buffer and new array assignment for shallowRef
  function appendSseEvent(
    eventName: string,
    level: SseLogLevel,
    message: string,
    payload: Record<string, unknown> = {}
  ): void {
    const id =
      typeof crypto !== 'undefined' && crypto.randomUUID
        ? crypto.randomUUID()
        : `sse-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`

    const newEvent: WorkspaceSseEvent = {
      id,
      timestamp: new Date().toISOString(),
      eventName,
      level,
      message,
      payload
    }

    const current = sseEvents.value
    if (current.length >= 500) {
      sseEvents.value = [...current.slice(current.length - 499), newEvent]
    } else {
      sseEvents.value = [...current, newEvent]
    }
  }

  // Actions
  async function fetchTools(force = false): Promise<ToolMetadata[]> {
    if (tools.value.length > 0 && !force) {
      return tools.value
    }
    loadingTools.value = true
    error.value = null
    try {
      const response = await http.get<ToolMetadata[]>('/tools')
      tools.value = response.data
      return response.data
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Fetch Tools',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unable to retrieve tool catalog'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      loadingTools.value = false
    }
  }

  async function fetchSteps(sessionId: string): Promise<StepSummaryResponse[]> {
    loadingSteps.value = true
    error.value = null
    try {
      const response = await http.get<StepSummaryResponse[]>(`/sessions/${sessionId}/steps`)
      steps.value = response.data
      if (!activeStepId.value && response.data.length > 0) {
        const latest = response.data[response.data.length - 1]
        await selectStep(sessionId, latest.executionId)
      }
      return response.data
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Fetch Steps',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unable to retrieve execution steps'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      loadingSteps.value = false
    }
  }

  async function selectStep(sessionId: string, stepId: string): Promise<void> {
    activeStepId.value = stepId
    await fetchStepDetail(sessionId, stepId)
  }

  async function fetchStepDetail(sessionId: string, stepId: string): Promise<StepDetailResponse> {
    const seq = ++detailRequestSeq
    loadingStepDetail.value = true
    error.value = null
    try {
      const response = await http.get<StepDetailResponse>(`/sessions/${sessionId}/steps/${stepId}`)
      if (seq === detailRequestSeq && activeStepId.value === stepId) {
        activeStepDetail.value = response.data
      }
      return response.data
    } catch (err) {
      if (seq === detailRequestSeq) {
        if (err instanceof ApiError) {
          error.value = err.problem
          throw err
        }
        const fallback: ProblemDetail = {
          title: 'Failed to Fetch Step Details',
          status: 500,
          detail: err instanceof Error ? err.message : 'Unable to retrieve step result'
        }
        error.value = fallback
        throw new ApiError(fallback)
      }
      throw err
    } finally {
      if (seq === detailRequestSeq) {
        loadingStepDetail.value = false
      }
    }
  }

  async function runTool(
    sessionId: string,
    toolId: string,
    customParams?: Record<string, unknown>
  ): Promise<ToolRunAcceptedResponse> {
    if (triggeringToolId.value !== null) {
      throw new Error('A tool execution is already in flight')
    }

    const paramsToPost: Record<string, unknown> = { ...(customParams || {}) }

    // Auto-resolve prerequisite stepId for offline analytical tools
    if (toolId === 'security_headers_score' && !paramsToPost.stepId) {
      const prerequisiteStepId =
        latestCompletedHttpHeadersStepId.value ||
        (activeStepDetail.value?.toolId === 'http_headers' &&
        activeStepDetail.value.status === 'COMPLETED'
          ? activeStepDetail.value.executionId
          : null)
      if (prerequisiteStepId) {
        paramsToPost.stepId = prerequisiteStepId
      }
    }

    if (toolId === 'cve_matcher' && !paramsToPost.stepId) {
      const prerequisiteStepId =
        latestCompletedTechDetectStepId.value ||
        (activeStepDetail.value?.toolId === 'tech_detect' &&
        activeStepDetail.value.status === 'COMPLETED'
          ? activeStepDetail.value.executionId
          : null)
      if (prerequisiteStepId) {
        paramsToPost.stepId = prerequisiteStepId
      }
    }

    triggeringToolId.value = toolId
    error.value = null

    try {
      const response = await http.post<ToolRunAcceptedResponse>(
        `/sessions/${sessionId}/tools/${toolId}/run`,
        paramsToPost
      )
      const accepted = response.data

      // Optimistically insert or update step in timeline
      const existingIdx = steps.value.findIndex((s) => s.executionId === accepted.executionId)
      if (existingIdx === -1) {
        steps.value = [
          ...steps.value,
          {
            executionId: accepted.executionId,
            toolId: accepted.toolId,
            status: accepted.status,
            durationMs: null,
            observationCount: 0,
            startedAt: accepted.enqueuedAt,
            endedAt: null
          }
        ]
      } else {
        const updated = [...steps.value]
        updated[existingIdx] = {
          ...updated[existingIdx],
          status: accepted.status
        }
        steps.value = updated
      }

      activeStepId.value = accepted.executionId
      activeStepDetail.value = {
        executionId: accepted.executionId,
        toolId: accepted.toolId,
        status: accepted.status,
        durationMs: null,
        failureReason: null,
        rawOutput: null,
        parsedData: {},
        score: null,
        observations: [],
        startedAt: accepted.enqueuedAt,
        endedAt: null
      }

      // Increment session stepCount in session store
      const sessionsStore = useSessionsStore()
      if (sessionsStore.currentSession && sessionsStore.currentSession.id === sessionId) {
        sessionsStore.currentSession.stepCount++
      }

      return accepted
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Tool Execution Failed',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unable to trigger tool execution'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      triggeringToolId.value = null
    }
  }

  async function requestStepComment(
    sessionId: string,
    stepId: string
  ): Promise<LlmAsyncAcceptedResponse> {
    requestingComment.value = true
    error.value = null
    try {
      const response = await http.post<LlmAsyncAcceptedResponse>(
        `/sessions/${sessionId}/llm/comment`,
        { stepId }
      )
      return response.data
    } catch (err) {
      requestingComment.value = false
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Request Advisory Comment',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unable to request LLM step analysis'
      }
      error.value = fallback
      throw new ApiError(fallback)
    }
  }

  async function sendChatMessage(
    sessionId: string,
    message: string
  ): Promise<LlmAsyncAcceptedResponse> {
    if (!message || !message.trim()) {
      throw new Error('Chat message cannot be blank')
    }
    const trimmed = message.trim()
    const id =
      typeof crypto !== 'undefined' && crypto.randomUUID
        ? crypto.randomUUID()
        : `msg-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`

    const userMsg: LlmChatMessage = {
      id,
      role: 'user',
      content: trimmed,
      timestamp: new Date().toISOString()
    }
    chatMessages.value = [...chatMessages.value, userMsg]
    sendingChat.value = true
    error.value = null

    try {
      const response = await http.post<LlmAsyncAcceptedResponse>(
        `/sessions/${sessionId}/llm/chat`,
        { message: trimmed }
      )
      return response.data
    } catch (err) {
      sendingChat.value = false
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Send Chat Message',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unable to send tactical chat query'
      }
      error.value = fallback
      throw new ApiError(fallback)
    }
  }

  function connectSse(sessionId: string): void {
    disconnectSse()

    sseConnectionState.value = 'CONNECTING'

    if (typeof EventSource === 'undefined') {
      sseConnectionState.value = 'ERROR'
      return
    }

    const es = new EventSource(`/api/sessions/${encodeURIComponent(sessionId)}/events`, {
      withCredentials: true
    })
    activeEventSource = es

    function parsePayload(event: MessageEvent): Record<string, unknown> {
      try {
        return event.data ? JSON.parse(event.data) : {}
      } catch {
        return { raw: event.data }
      }
    }

    es.addEventListener('connected', (e: MessageEvent) => {
      sseConnectionState.value = 'CONNECTED'
      appendSseEvent('connected', 'INFO', 'Connected to session live event stream', parsePayload(e))
    })

    es.addEventListener('step_queued', (e: MessageEvent) => {
      const data = parsePayload(e)
      const toolId = String(data.toolId || 'Tool')
      appendSseEvent('step_queued', 'INFO', `Queued ${toolId} for background execution`, data)

      if (data.executionId) {
        const execId = String(data.executionId)
        const idx = steps.value.findIndex((s) => s.executionId === execId)
        if (idx === -1) {
          steps.value = [
            ...steps.value,
            {
              executionId: execId,
              toolId: String(data.toolId || ''),
              status: 'PENDING',
              durationMs: null,
              observationCount: 0,
              startedAt: null,
              endedAt: null
            }
          ]
        } else {
          const updated = [...steps.value]
          updated[idx] = { ...updated[idx], status: 'PENDING' }
          steps.value = updated
        }
        if (!activeStepId.value || activeStepId.value === execId) {
          activeStepId.value = execId
          if (activeStepDetail.value?.executionId !== execId) {
            activeStepDetail.value = {
              executionId: execId,
              toolId: String(data.toolId || ''),
              status: 'PENDING',
              durationMs: null,
              failureReason: null,
              rawOutput: null,
              parsedData: {},
              score: null,
              observations: [],
              startedAt: null,
              endedAt: null
            }
          }
        }
      }
    })

    es.addEventListener('step_started', (e: MessageEvent) => {
      const data = parsePayload(e)
      const toolId = String(data.toolId || 'Tool')
      appendSseEvent('step_started', 'INFO', `Started execution for ${toolId}`, data)

      if (data.executionId) {
        const execId = String(data.executionId)
        const startedAt = typeof data.startedAt === 'string' ? data.startedAt : null
        const idx = steps.value.findIndex((s) => s.executionId === execId)
        if (idx !== -1) {
          const updated = [...steps.value]
          updated[idx] = {
            ...updated[idx],
            status: 'RUNNING',
            startedAt: startedAt || updated[idx].startedAt
          }
          steps.value = updated
        }
        if (activeStepDetail.value?.executionId === execId) {
          activeStepDetail.value = {
            ...activeStepDetail.value,
            status: 'RUNNING',
            startedAt: startedAt || activeStepDetail.value.startedAt
          }
        }
      }
    })

    es.addEventListener('step_finished', (e: MessageEvent) => {
      const data = parsePayload(e)
      const toolId = String(data.toolId || 'Tool')
      const durationMs = typeof data.durationMs === 'number' ? data.durationMs : 0
      const observationCount = typeof data.observationCount === 'number' ? data.observationCount : 0
      appendSseEvent(
        'step_finished',
        'SUCCESS',
        `${toolId} completed in ${durationMs}ms (${observationCount} observations)`,
        data
      )

      if (data.executionId) {
        const execId = String(data.executionId)
        const idx = steps.value.findIndex((s) => s.executionId === execId)
        if (idx !== -1) {
          const updated = [...steps.value]
          updated[idx] = {
            ...updated[idx],
            status: 'COMPLETED',
            durationMs,
            observationCount
          }
          steps.value = updated
        }
        if (!activeStepId.value || activeStepId.value === execId) {
          fetchStepDetail(sessionId, execId).catch(() => {})
        }
        fetchSteps(sessionId).catch(() => {})
      }
    })

    es.addEventListener('step_failed', (e: MessageEvent) => {
      const data = parsePayload(e)
      const reason = String(data.failureReason || 'Execution error')
      appendSseEvent('step_failed', 'ERROR', `Step failed: ${reason}`, data)

      if (data.executionId) {
        const execId = String(data.executionId)
        const idx = steps.value.findIndex((s) => s.executionId === execId)
        if (idx !== -1) {
          const updated = [...steps.value]
          updated[idx] = {
            ...updated[idx],
            status: 'FAILED'
          }
          steps.value = updated
        }
        if (activeStepId.value === execId) {
          fetchStepDetail(sessionId, execId).catch(() => {})
        }
      }
    })

    es.addEventListener('policy_alert', (e: MessageEvent) => {
      const data = parsePayload(e)
      const message = String(data.message || 'Policy evaluation alert')
      appendSseEvent('policy_alert', 'WARN', `Policy Alert: ${message}`, data)
      policyAlertMessage.value = message
    })

    es.addEventListener('session_completed', (e: MessageEvent) => {
      const data = parsePayload(e)
      appendSseEvent('session_completed', 'SUCCESS', 'Audit session marked COMPLETED', data)
      requestingComment.value = false
      sendingChat.value = false
      const sessionsStore = useSessionsStore()
      if (sessionsStore.currentSession && sessionsStore.currentSession.id === sessionId) {
        sessionsStore.currentSession.state = 'COMPLETED'
      }
    })

    es.addEventListener('session_aborted', (e: MessageEvent) => {
      const data = parsePayload(e)
      appendSseEvent('session_aborted', 'WARN', 'Audit session ABORTED', data)
      requestingComment.value = false
      sendingChat.value = false
      const sessionsStore = useSessionsStore()
      if (sessionsStore.currentSession && sessionsStore.currentSession.id === sessionId) {
        sessionsStore.currentSession.state = 'ABORTED'
      }
      // Transition pending/running steps to CANCELLED
      steps.value = steps.value.map((s) =>
        s.status === 'PENDING' || s.status === 'RUNNING' ? { ...s, status: 'CANCELLED' } : s
      )
      if (
        activeStepDetail.value &&
        (activeStepDetail.value.status === 'PENDING' || activeStepDetail.value.status === 'RUNNING')
      ) {
        activeStepDetail.value = { ...activeStepDetail.value, status: 'CANCELLED' }
      }
    })

    es.addEventListener('llm_comment_ready', (e: MessageEvent) => {
      const data = parsePayload(e)
      appendSseEvent('llm_comment_ready', 'INFO', 'LLM Advisor commentary ready', data)
      latestAdvisory.value = {
        stepId: String(data.stepId || ''),
        toolId: data.toolId ? String(data.toolId) : undefined,
        comment: String(data.comment || ''),
        suggestedTool: data.suggestedTool ? String(data.suggestedTool) : null,
        suggestedReason: data.suggestedReason ? String(data.suggestedReason) : null,
        timestamp: typeof data.timestamp === 'string' ? data.timestamp : new Date().toISOString()
      }
      requestingComment.value = false
    })

    es.addEventListener('llm_chat_reply', (e: MessageEvent) => {
      const data = parsePayload(e)
      appendSseEvent('llm_chat_reply', 'INFO', 'LLM Advisor chat reply received', data)
      const id =
        typeof crypto !== 'undefined' && crypto.randomUUID
          ? crypto.randomUUID()
          : `reply-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`
      const replyMsg: LlmChatMessage = {
        id,
        role: 'assistant',
        content: String(data.reply || ''),
        timestamp: typeof data.timestamp === 'string' ? data.timestamp : new Date().toISOString()
      }
      chatMessages.value = [...chatMessages.value, replyMsg]
      sendingChat.value = false
    })

    es.onerror = () => {
      sseConnectionState.value = 'ERROR'
      requestingComment.value = false
      sendingChat.value = false
    }
  }

  function disconnectSse(): void {
    if (activeEventSource) {
      activeEventSource.close()
      activeEventSource = null
    }
    sseConnectionState.value = 'DISCONNECTED'
  }

  function clearSseEvents(): void {
    sseEvents.value = []
  }

  function dismissPolicyAlert(): void {
    policyAlertMessage.value = null
  }

  function clearError(): void {
    error.value = null
  }

  function syncSessionFindingCount(sessionId: string): void {
    const sessionsStore = useSessionsStore()
    const count = activeFindingsCount.value
    if (sessionsStore.currentSession && sessionsStore.currentSession.id === sessionId) {
      sessionsStore.currentSession.findingCount = count
    }
    const idx = sessionsStore.sessions.findIndex((s) => s.id === sessionId)
    if (idx !== -1) {
      sessionsStore.sessions[idx] = {
        ...sessionsStore.sessions[idx],
        findingCount: count
      }
    }
  }

  async function fetchFindings(sessionId: string): Promise<Finding[]> {
    loadingFindings.value = true
    error.value = null
    try {
      const response = await http.get<Finding[]>(`/sessions/${sessionId}/findings`)
      findings.value = response.data
      syncSessionFindingCount(sessionId)
      return response.data
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Fetch Findings',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unable to retrieve session findings'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      loadingFindings.value = false
    }
  }

  async function createFinding(sessionId: string, payload: CreateFindingRequest): Promise<Finding> {
    submittingFinding.value = true
    error.value = null
    try {
      const response = await http.post<Finding>(`/sessions/${sessionId}/findings`, payload)
      const created = response.data
      findings.value.push(created)
      syncSessionFindingCount(sessionId)
      return created
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Create Finding',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unable to create finding'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      submittingFinding.value = false
    }
  }

  async function updateFinding(sessionId: string, findingId: string, payload: UpdateFindingRequest): Promise<Finding> {
    submittingFinding.value = true
    error.value = null
    try {
      const response = await http.patch<Finding>(`/sessions/${sessionId}/findings/${findingId}`, payload)
      const updated = response.data
      const idx = findings.value.findIndex((f) => f.id === findingId)
      if (idx !== -1) {
        findings.value[idx] = updated
      } else {
        findings.value.push(updated)
      }
      syncSessionFindingCount(sessionId)
      return updated
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Update Finding',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unable to update finding'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      submittingFinding.value = false
    }
  }

  async function addEvidence(sessionId: string, findingId: string, payload: CreateEvidenceRequest): Promise<EvidenceItem> {
    submittingFinding.value = true
    error.value = null
    try {
      const response = await http.post<EvidenceItem>(`/sessions/${sessionId}/findings/${findingId}/evidence`, payload)
      const evidenceItem = response.data
      const finding = findings.value.find((f) => f.id === findingId)
      if (finding) {
        if (!finding.evidence) {
          finding.evidence = []
        }
        finding.evidence.push(evidenceItem)
      }
      return evidenceItem
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Attach Evidence',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unable to attach evidence'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      submittingFinding.value = false
    }
  }

  async function fetchReportHtml(sessionId: string): Promise<string> {
    error.value = null
    try {
      const response = await http.get<string>(`/sessions/${sessionId}/report`, {
        responseType: 'text',
        headers: {
          Accept: 'text/html, application/xhtml+xml, application/problem+json;q=0.9, */*;q=0.8'
        }
      })
      return response.data
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Fetch Report',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unable to retrieve session report'
      }
      error.value = fallback
      throw new ApiError(fallback)
    }
  }

  function resetWorkspace(): void {
    disconnectSse()
    steps.value = []
    activeStepId.value = null
    activeStepDetail.value = null
    sseEvents.value = []
    policyAlertMessage.value = null
    triggeringToolId.value = null
    error.value = null
    latestAdvisory.value = null
    chatMessages.value = []
    requestingComment.value = false
    sendingChat.value = false
    findings.value = []
    loadingFindings.value = false
    submittingFinding.value = false
  }

  return {
    // State
    tools,
    steps,
    activeStepId,
    activeStepDetail,
    sseEvents,
    sseConnectionState,
    policyAlertMessage,
    latestAdvisory,
    chatMessages,
    requestingComment,
    sendingChat,
    loadingTools,
    loadingSteps,
    loadingStepDetail,
    triggeringToolId,
    error,
    findings,
    loadingFindings,
    submittingFinding,

    // Getters
    toolsByTier,
    hasActiveExecution,
    latestCompletedHttpHeadersStepId,
    latestCompletedTechDetectStepId,
    activeFindingsCount,

    // Actions
    appendSseEvent,
    fetchTools,
    fetchSteps,
    selectStep,
    fetchStepDetail,
    runTool,
    requestStepComment,
    sendChatMessage,
    connectSse,
    disconnectSse,
    clearSseEvents,
    dismissPolicyAlert,
    clearError,
    resetWorkspace,
    fetchFindings,
    createFinding,
    updateFinding,
    addEvidence,
    fetchReportHtml
  }
})
