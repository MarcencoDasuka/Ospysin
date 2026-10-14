import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { http, ApiError } from '@/api/http'
import type { AuthUser, LoginRequest, ProblemDetail } from '@/api/types'

describe('Pinia Auth Store (useAuthStore)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('fetchCurrentUser()', () => {
    it('successfully retrieves authenticated operator profile', async () => {
      const mockUser: AuthUser = {
        id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
        username: 'admin',
        role: 'ADMIN'
      }

      vi.spyOn(http, 'get').mockResolvedValueOnce({
        data: mockUser,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any
      })

      const store = useAuthStore()
      expect(store.status).toBe('idle')
      expect(store.user).toBeNull()

      const result = await store.fetchCurrentUser()
      expect(result).toEqual(mockUser)
      expect(store.user).toEqual(mockUser)
      expect(store.status).toBe('authenticated')
      expect(store.error).toBeNull()
    })

    it('sets unauthenticated status and keeps error null on 401 response (normal guest state)', async () => {
      const problem: ProblemDetail = {
        title: 'Unauthorized',
        status: 401,
        detail: 'No active session'
      }

      vi.spyOn(http, 'get').mockRejectedValueOnce(new ApiError(problem))

      const store = useAuthStore()
      const result = await store.fetchCurrentUser()

      expect(result).toBeNull()
      expect(store.user).toBeNull()
      expect(store.status).toBe('unauthenticated')
      expect(store.error).toBeNull()
    })

    it('sets unauthenticated status and records error on non-401 response (e.g. 500)', async () => {
      const problem: ProblemDetail = {
        title: 'Internal Server Error',
        status: 500,
        detail: 'Database unreachable'
      }

      vi.spyOn(http, 'get').mockRejectedValueOnce(new ApiError(problem))

      const store = useAuthStore()
      const result = await store.fetchCurrentUser()

      expect(result).toBeNull()
      expect(store.user).toBeNull()
      expect(store.status).toBe('unauthenticated')
      expect(store.error).toEqual(problem)
    })

    it('handles unexpected non-ApiError failures gracefully during fetchCurrentUser', async () => {
      vi.spyOn(http, 'get').mockRejectedValueOnce(new Error('Network offline'))

      const store = useAuthStore()
      const result = await store.fetchCurrentUser()

      expect(result).toBeNull()
      expect(store.user).toBeNull()
      expect(store.status).toBe('unauthenticated')
      expect(store.error?.status).toBe(500)
      expect(store.error?.title).toBe('Authentication Error')
    })
  })

  describe('login()', () => {
    const credentials: LoginRequest = {
      username: 'admin',
      password: 'validPassword123'
    }

    it('authenticates operator and updates state to authenticated on success', async () => {
      const mockUser: AuthUser = {
        id: 'admin-uuid',
        username: 'admin',
        role: 'ADMIN'
      }

      vi.spyOn(http, 'post').mockResolvedValueOnce({
        data: mockUser,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any
      })

      const store = useAuthStore()
      const result = await store.login(credentials)

      expect(result).toEqual(mockUser)
      expect(store.user).toEqual(mockUser)
      expect(store.status).toBe('authenticated')
      expect(store.error).toBeNull()
    })

    it('sets error and re-throws on invalid credentials (401)', async () => {
      const problem: ProblemDetail = {
        type: 'https://ospysin.dev/errors/unauthorized',
        title: 'Unauthorized',
        status: 401,
        detail: 'Invalid credentials provided'
      }

      vi.spyOn(http, 'post').mockRejectedValueOnce(new ApiError(problem))

      const store = useAuthStore()
      await expect(store.login(credentials)).rejects.toThrow(ApiError)

      expect(store.user).toBeNull()
      expect(store.status).toBe('unauthenticated')
      expect(store.error).toEqual(problem)
    })

    it('sets error and re-throws on validation error with invalidParams (422)', async () => {
      const problem: ProblemDetail = {
        type: 'https://ospysin.dev/errors/validation-error',
        title: 'Validation Error',
        status: 422,
        detail: 'Input validation failed',
        invalidParams: [{ name: 'password', reason: 'Must not be blank' }]
      }

      vi.spyOn(http, 'post').mockRejectedValueOnce(new ApiError(problem))

      const store = useAuthStore()
      await expect(store.login(credentials)).rejects.toThrow(ApiError)

      expect(store.user).toBeNull()
      expect(store.status).toBe('unauthenticated')
      expect(store.error?.invalidParams).toHaveLength(1)
    })

    it('handles unexpected exceptions and re-throws ApiError', async () => {
      vi.spyOn(http, 'post').mockRejectedValueOnce(new Error('Connection refused'))

      const store = useAuthStore()
      await expect(store.login(credentials)).rejects.toThrow(ApiError)

      expect(store.user).toBeNull()
      expect(store.status).toBe('unauthenticated')
      expect(store.error?.status).toBe(500)
    })
  })

  describe('logout()', () => {
    it('resets user, status, and error state on logout', async () => {
      const store = useAuthStore()
      store.user = { id: '1', username: 'admin', role: 'ADMIN' }
      store.status = 'authenticated'
      store.error = { title: 'Previous Error' }

      vi.spyOn(http, 'post').mockResolvedValueOnce({
        data: null,
        status: 204,
        statusText: 'No Content',
        headers: {},
        config: {} as any
      })

      await store.logout()

      expect(store.user).toBeNull()
      expect(store.status).toBe('unauthenticated')
      expect(store.error).toBeNull()
    })

    it('resets local state even if logout HTTP request encounters a network error', async () => {
      const store = useAuthStore()
      store.user = { id: '1', username: 'admin', role: 'ADMIN' }
      store.status = 'authenticated'

      vi.spyOn(http, 'post').mockRejectedValueOnce(new Error('Network drop'))

      await store.logout()

      expect(store.user).toBeNull()
      expect(store.status).toBe('unauthenticated')
      expect(store.error).toBeNull()
    })
  })

  describe('clearError()', () => {
    it('clears active problem detail error from state', () => {
      const store = useAuthStore()
      store.error = { title: 'Some error' }
      store.clearError()
      expect(store.error).toBeNull()
    })
  })
})
