import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useSessionsStore } from '@/stores/sessions'
import { http, ApiError } from '@/api/http'
import type {
  AuditSession,
  CreateSessionRequest,
  SessionPageResponse,
  ProblemDetail
} from '@/api/types'

describe('Pinia Sessions Store (useSessionsStore)', () => {
  const mockSession: AuditSession = {
    id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
    targetUrl: 'https://example.com',
    mode: 'PUBLIC',
    state: 'ACTIVE',
    scopeAcknowledged: true,
    scopeAckVersion: '1.0.0',
    scopeAckHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    scopeAckTimestamp: '2026-10-09T01:40:00Z',
    stepCount: 4,
    findingCount: 2,
    createdAt: '2026-10-09T01:40:00Z',
    updatedAt: '2026-10-09T01:40:00Z'
  }

  beforeEach(() => {
    setActivePinia(createPinia())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('fetchSessions()', () => {
    it('successfully retrieves paginated sessions and updates store state', async () => {
      const pageResponse: SessionPageResponse = {
        content: [mockSession],
        page: 0,
        size: 20,
        totalElements: 1,
        totalPages: 1
      }

      vi.spyOn(http, 'get').mockResolvedValueOnce({
        data: pageResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any
      })

      const store = useSessionsStore()
      expect(store.sessions).toEqual([])
      expect(store.loading).toBe(false)

      const result = await store.fetchSessions(0, 20)

      expect(result).toEqual(pageResponse)
      expect(store.sessions).toEqual([mockSession])
      expect(store.page).toBe(0)
      expect(store.size).toBe(20)
      expect(store.totalElements).toBe(1)
      expect(store.totalPages).toBe(1)
      expect(store.loading).toBe(false)
      expect(store.error).toBeNull()
    })

    it('captures RFC 9457 error when fetching sessions fails', async () => {
      const problem: ProblemDetail = {
        title: 'Internal Server Error',
        status: 500,
        detail: 'Database connectivity failure'
      }

      vi.spyOn(http, 'get').mockRejectedValueOnce(new ApiError(problem))

      const store = useSessionsStore()

      await expect(store.fetchSessions(0, 20)).rejects.toThrow()
      expect(store.error).toEqual(problem)
      expect(store.loading).toBe(false)
    })

    it('wraps generic errors in a fallback ProblemDetail', async () => {
      vi.spyOn(http, 'get').mockRejectedValueOnce(new Error('Network error'))

      const store = useSessionsStore()

      await expect(store.fetchSessions(0, 20)).rejects.toThrow()
      expect(store.error).toEqual({
        title: 'Failed to Fetch Sessions',
        status: 500,
        detail: 'Network error'
      })
      expect(store.loading).toBe(false)
    })
  })

  describe('fetchSessionById()', () => {
    it('successfully retrieves a single session and updates currentSession', async () => {
      vi.spyOn(http, 'get').mockResolvedValueOnce({
        data: mockSession,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any
      })

      const store = useSessionsStore()
      const result = await store.fetchSessionById(mockSession.id)

      expect(result).toEqual(mockSession)
      expect(store.currentSession).toEqual(mockSession)
      expect(store.loading).toBe(false)
      expect(store.error).toBeNull()
    })

    it('captures 404 Not Found error into store.error', async () => {
      const problem: ProblemDetail = {
        title: 'Session Not Found',
        status: 404,
        detail: `Session ${mockSession.id} does not exist`
      }

      vi.spyOn(http, 'get').mockRejectedValueOnce(new ApiError(problem))

      const store = useSessionsStore()

      await expect(store.fetchSessionById(mockSession.id)).rejects.toThrow()
      expect(store.error).toEqual(problem)
      expect(store.loading).toBe(false)
    })

    it('clears stale currentSession before issuing the GET request to avoid masking errors', async () => {
      const store = useSessionsStore()
      store.currentSession = { ...mockSession, id: 'stale-id' }

      vi.spyOn(http, 'get').mockRejectedValueOnce(
        new ApiError({ title: 'Not Found', status: 404, detail: 'Not found' })
      )

      await expect(store.fetchSessionById('non-existent-id')).rejects.toThrow()
      expect(store.currentSession).toBeNull()
    })
  })

  describe('createSession()', () => {
    const payload: CreateSessionRequest = {
      targetUrl: 'https://example.com',
      mode: 'PUBLIC',
      scopeAcknowledged: true,
      scopeAckVersion: '1.0.0'
    }

    it('successfully creates session, prepends to list, and updates currentSession', async () => {
      vi.spyOn(http, 'post').mockResolvedValueOnce({
        data: mockSession,
        status: 201,
        statusText: 'Created',
        headers: {},
        config: {} as any
      })

      const store = useSessionsStore()
      const result = await store.createSession(payload)

      expect(result).toEqual(mockSession)
      expect(store.currentSession).toEqual(mockSession)
      expect(store.sessions).toEqual([mockSession])
      expect(store.totalElements).toBe(1)
      expect(store.creating).toBe(false)
      expect(store.error).toBeNull()
    })

    it('slices sessions list to size and recalculates totalPages when new session is created', async () => {
      const store = useSessionsStore()
      store.size = 2
      store.totalElements = 2
      store.totalPages = 1
      store.sessions = [
        { ...mockSession, id: 'session-1' },
        { ...mockSession, id: 'session-2' }
      ]

      const newSession: AuditSession = { ...mockSession, id: 'session-3' }
      vi.spyOn(http, 'post').mockResolvedValueOnce({
        data: newSession,
        status: 201,
        statusText: 'Created',
        headers: {},
        config: {} as any
      })

      await store.createSession(payload)

      expect(store.totalElements).toBe(3)
      expect(store.totalPages).toBe(2)
      expect(store.sessions.length).toBe(2)
      expect(store.sessions[0].id).toBe('session-3')
      expect(store.sessions[1].id).toBe('session-1')
    })

    it('blocks concurrent duplicate creation calls when creating is true', async () => {
      const store = useSessionsStore()
      store.creating = true

      await expect(store.createSession(payload)).rejects.toThrow(
        'A session creation request is already in flight'
      )
    })

    it('captures 403 Forbidden PolicyEngine rejection with invalidParams', async () => {
      const problem: ProblemDetail = {
        title: 'Scope Policy Violation',
        status: 403,
        detail: 'Target resolved to special-purpose IP blocked in PUBLIC mode',
        invalidParams: [
          { name: 'targetUrl', reason: 'Loopback and private IPs are blocked in PUBLIC mode' }
        ]
      }

      vi.spyOn(http, 'post').mockRejectedValueOnce(new ApiError(problem))

      const store = useSessionsStore()

      await expect(store.createSession(payload)).rejects.toThrow()
      expect(store.error).toEqual(problem)
      expect(store.creating).toBe(false)
    })

    it('captures 422 Unprocessable Entity validation errors', async () => {
      const problem: ProblemDetail = {
        title: 'Validation Failed',
        status: 422,
        detail: 'Scope attestation failed',
        invalidParams: [
          { name: 'scopeAcknowledged', reason: 'Scope acknowledgment must be explicitly agreed to' }
        ]
      }

      vi.spyOn(http, 'post').mockRejectedValueOnce(new ApiError(problem))

      const store = useSessionsStore()

      await expect(store.createSession(payload)).rejects.toThrow()
      expect(store.error).toEqual(problem)
      expect(store.creating).toBe(false)
    })
  })

  describe('completeSession()', () => {
    it('successfully transitions session to COMPLETED and updates store references', async () => {
      const completedSession: AuditSession = {
        ...mockSession,
        state: 'COMPLETED'
      }

      vi.spyOn(http, 'post').mockResolvedValueOnce({
        data: completedSession,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any
      })

      const store = useSessionsStore()
      store.sessions = [{ ...mockSession }]
      store.currentSession = { ...mockSession }

      const result = await store.completeSession(mockSession.id)

      expect(result.state).toBe('COMPLETED')
      expect(store.currentSession?.state).toBe('COMPLETED')
      expect(store.sessions[0].state).toBe('COMPLETED')
      expect(store.loading).toBe(false)
    })

    it('captures 409 Conflict when completing session with running background executions', async () => {
      const problem: ProblemDetail = {
        title: 'Session Conflict',
        status: 409,
        detail: 'Cannot complete session while 1 executions are PENDING or RUNNING'
      }

      vi.spyOn(http, 'post').mockRejectedValueOnce(new ApiError(problem))

      const store = useSessionsStore()

      await expect(store.completeSession(mockSession.id)).rejects.toThrow()
      expect(store.error).toEqual(problem)
      expect(store.loading).toBe(false)
    })
  })

  describe('abortSession()', () => {
    it('successfully terminates session to ABORTED and updates store references', async () => {
      const abortedSession: AuditSession = {
        ...mockSession,
        state: 'ABORTED'
      }

      vi.spyOn(http, 'post').mockResolvedValueOnce({
        data: abortedSession,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any
      })

      const store = useSessionsStore()
      store.sessions = [{ ...mockSession }]
      store.currentSession = { ...mockSession }

      const result = await store.abortSession(mockSession.id)

      expect(result.state).toBe('ABORTED')
      expect(store.currentSession?.state).toBe('ABORTED')
      expect(store.sessions[0].state).toBe('ABORTED')
      expect(store.loading).toBe(false)
    })
  })

  describe('clearError()', () => {
    it('clears reactive error state', () => {
      const store = useSessionsStore()
      store.error = {
        title: 'Sample Error',
        status: 400,
        detail: 'Sample detail'
      }

      store.clearError()
      expect(store.error).toBeNull()
    })
  })
})
