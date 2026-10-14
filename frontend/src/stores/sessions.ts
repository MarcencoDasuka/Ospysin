import { defineStore } from 'pinia'
import { ref } from 'vue'
import { http, ApiError } from '@/api/http'
import type {
  AuditSession,
  CreateSessionRequest,
  SessionPageResponse,
  ProblemDetail
} from '@/api/types'

export const useSessionsStore = defineStore('sessions', () => {
  const sessions = ref<AuditSession[]>([])
  const currentSession = ref<AuditSession | null>(null)
  const page = ref(0)
  const size = ref(20)
  const totalElements = ref(0)
  const totalPages = ref(0)
  const loading = ref(false)
  const creating = ref(false)
  const error = ref<ProblemDetail | null>(null)

  async function fetchSessions(pageNumber = 0, pageSize = 20): Promise<SessionPageResponse> {
    loading.value = true
    error.value = null
    try {
      const response = await http.get<SessionPageResponse>('/sessions', {
        params: { page: pageNumber, size: pageSize }
      })
      sessions.value = response.data.content
      page.value = response.data.page
      size.value = response.data.size
      totalElements.value = response.data.totalElements
      totalPages.value = response.data.totalPages
      return response.data
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Fetch Sessions',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unknown error while fetching sessions'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      loading.value = false
    }
  }

  async function fetchSessionById(id: string): Promise<AuditSession> {
    loading.value = true
    error.value = null
    currentSession.value = null
    try {
      const response = await http.get<AuditSession>(`/sessions/${id}`)
      currentSession.value = response.data
      return response.data
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Session Not Found',
        status: 404,
        detail: err instanceof Error ? err.message : 'Unable to retrieve session'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      loading.value = false
    }
  }

  async function createSession(payload: CreateSessionRequest): Promise<AuditSession> {
    if (creating.value) {
      throw new Error('A session creation request is already in flight')
    }
    creating.value = true
    error.value = null
    try {
      const response = await http.post<AuditSession>('/sessions', payload)
      const created = response.data
      currentSession.value = created
      totalElements.value = totalElements.value + 1
      sessions.value = [created, ...sessions.value.filter((s) => s.id !== created.id)].slice(
        0,
        size.value
      )
      totalPages.value = Math.max(1, Math.ceil(totalElements.value / size.value))
      return created
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Session Creation Failed',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unknown error during session creation'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      creating.value = false
    }
  }

  async function completeSession(id: string): Promise<AuditSession> {
    loading.value = true
    error.value = null
    try {
      const response = await http.post<AuditSession>(`/sessions/${id}/complete`)
      const updated = response.data
      if (currentSession.value?.id === id) {
        currentSession.value = updated
      }
      const idx = sessions.value.findIndex((s) => s.id === id)
      if (idx !== -1) {
        sessions.value[idx] = updated
      }
      return updated
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Complete Session',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unknown error while completing session'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      loading.value = false
    }
  }

  async function abortSession(id: string): Promise<AuditSession> {
    loading.value = true
    error.value = null
    try {
      const response = await http.post<AuditSession>(`/sessions/${id}/abort`)
      const updated = response.data
      if (currentSession.value?.id === id) {
        currentSession.value = updated
      }
      const idx = sessions.value.findIndex((s) => s.id === id)
      if (idx !== -1) {
        sessions.value[idx] = updated
      }
      return updated
    } catch (err) {
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallback: ProblemDetail = {
        title: 'Failed to Abort Session',
        status: 500,
        detail: err instanceof Error ? err.message : 'Unknown error while aborting session'
      }
      error.value = fallback
      throw new ApiError(fallback)
    } finally {
      loading.value = false
    }
  }

  function clearError(): void {
    error.value = null
  }

  return {
    sessions,
    currentSession,
    page,
    size,
    totalElements,
    totalPages,
    loading,
    creating,
    error,
    fetchSessions,
    fetchSessionById,
    createSession,
    completeSession,
    abortSession,
    clearError
  }
})
