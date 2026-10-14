import { defineStore } from 'pinia'
import { ref } from 'vue'
import { http, ApiError, setUnauthorizedCallback } from '@/api/http'
import type { AuthUser, LoginRequest, ProblemDetail } from '@/api/types'

export type AuthStatus = 'idle' | 'loading' | 'authenticated' | 'unauthenticated'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<AuthUser | null>(null)
  const status = ref<AuthStatus>('idle')
  const error = ref<ProblemDetail | null>(null)

  // Configure automatic session eviction on 401 Unauthorized API responses
  setUnauthorizedCallback(() => {
    user.value = null
    status.value = 'unauthenticated'
  })

  async function fetchCurrentUser(): Promise<AuthUser | null> {
    status.value = 'loading'
    error.value = null
    try {
      const response = await http.get<AuthUser>('/auth/me')
      user.value = response.data
      status.value = 'authenticated'
      return response.data
    } catch (err) {
      user.value = null
      status.value = 'unauthenticated'
      if (err instanceof ApiError && err.status === 401) {
        // Cold-start session check returning 401 represents normal guest state, not a failed login error
        error.value = null
      } else if (err instanceof ApiError) {
        error.value = err.problem
      } else {
        error.value = {
          title: 'Authentication Error',
          status: 500,
          detail: 'Unable to retrieve authenticated operator session'
        }
      }
      return null
    }
  }

  async function login(credentials: LoginRequest): Promise<AuthUser> {
    status.value = 'loading'
    error.value = null
    try {
      const response = await http.post<AuthUser>('/auth/login', credentials)
      user.value = response.data
      status.value = 'authenticated'
      return response.data
    } catch (err) {
      user.value = null
      status.value = 'unauthenticated'
      if (err instanceof ApiError) {
        error.value = err.problem
        throw err
      }
      const fallbackProblem: ProblemDetail = {
        title: 'Login Failed',
        status: 500,
        detail: 'An unexpected error occurred during login'
      }
      error.value = fallbackProblem
      throw new ApiError(fallbackProblem)
    }
  }

  async function logout(): Promise<void> {
    status.value = 'loading'
    try {
      await http.post('/auth/logout')
    } catch {
      // Regardless of network failures, clear local state immediately
    } finally {
      user.value = null
      status.value = 'unauthenticated'
      error.value = null
    }
  }

  function clearError(): void {
    error.value = null
  }

  return {
    user,
    status,
    error,
    fetchCurrentUser,
    login,
    logout,
    clearError
  }
})
