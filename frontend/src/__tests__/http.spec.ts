import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import axios, { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios'
import {
  http,
  ApiError,
  getCookie,
  setUnauthorizedCallback,
  getUnauthorizedCallback
} from '@/api/http'
import type { ProblemDetail } from '@/api/types'

describe('Typed RFC 9457 API Client & CSRF Handler (http.ts)', () => {
  const originalAdapter = http.defaults.adapter

  beforeEach(() => {
    // Clear cookies
    document.cookie = 'XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'
    setUnauthorizedCallback(null)
  })

  afterEach(() => {
    http.defaults.adapter = originalAdapter
    vi.restoreAllMocks()
  })

  function createErrorResponse(
    status: number,
    data: unknown,
    code = 'ERR_BAD_RESPONSE'
  ): AxiosError {
    const config = {
      headers: new axios.AxiosHeaders(),
      method: 'post',
      url: '/test'
    } as InternalAxiosRequestConfig

    const response: AxiosResponse = {
      data,
      status,
      statusText: status === 401 ? 'Unauthorized' : 'Error',
      headers: {},
      config
    }

    return new AxiosError(
      `Request failed with status code ${status}`,
      code,
      config,
      null,
      response
    )
  }

  describe('getCookie utility', () => {
    it('returns null when document.cookie is empty', () => {
      document.cookie = 'dummy=1; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'
      expect(getCookie('NON_EXISTENT')).toBeNull()
    })

    it('extracts cookie when present at the beginning, middle, or end of cookie string', () => {
      document.cookie = 'XSRF-TOKEN=token-alpha; path=/'
      expect(getCookie('XSRF-TOKEN')).toBe('token-alpha')

      document.cookie = 'first=1; path=/'
      document.cookie = 'second=2; path=/'
      document.cookie = 'XSRF-TOKEN=token-beta; path=/'
      expect(getCookie('XSRF-TOKEN')).toBe('token-beta')
    })

    it('decodes URI encoded cookie values correctly', () => {
      document.cookie = 'XSRF-TOKEN=' + encodeURIComponent('token%with spaces');
      expect(getCookie('XSRF-TOKEN')).toBe('token%with spaces')
    })

    it('handles special regex metacharacters in cookie names without throwing regex syntax errors', () => {
      document.cookie = 'special[name].cookie=secret-val; path=/'
      expect(getCookie('special[name].cookie')).toBe('secret-val')
    })

    it('safely falls back to raw cookie value if URI decoding fails with URIError', () => {
      document.cookie = 'XSRF-TOKEN=%E0%A4%A; path=/'
      expect(getCookie('XSRF-TOKEN')).toBe('%E0%A4%A')
    })
  })

  describe('CSRF Token Header Propagation', () => {
    it('injects X-XSRF-TOKEN header on mutating POST requests when cookie is present', async () => {
      document.cookie = 'XSRF-TOKEN=csrf-test-token-123; path=/'
      let capturedConfig: InternalAxiosRequestConfig | undefined = undefined

      http.defaults.adapter = async (config) => {
        capturedConfig = config
        return {
          data: { status: 'OK' },
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        }
      }

      await http.post('/test/resource', { name: 'sample' })
      expect(capturedConfig).toBeDefined()
      expect((capturedConfig as unknown as InternalAxiosRequestConfig).headers['X-XSRF-TOKEN']).toBe('csrf-test-token-123')
    })

    it('injects X-XSRF-TOKEN header on mutating PUT, PATCH, and DELETE requests', async () => {
      document.cookie = 'XSRF-TOKEN=mutating-csrf-token; path=/'
      const methods = ['put', 'patch', 'delete'] as const

      for (const method of methods) {
        let capturedConfig: InternalAxiosRequestConfig | undefined = undefined
        http.defaults.adapter = async (config) => {
          capturedConfig = config
          return { data: {}, status: 200, statusText: 'OK', headers: {}, config }
        }

        if (method === 'delete') {
          await http.delete('/test/1')
        } else {
          await http[method]('/test/1', { test: true })
        }

        expect((capturedConfig as unknown as InternalAxiosRequestConfig).headers['X-XSRF-TOKEN']).toBe('mutating-csrf-token')
      }
    })

    it('does not inject X-XSRF-TOKEN when cookie is absent', async () => {
      let capturedConfig: InternalAxiosRequestConfig | undefined = undefined
      http.defaults.adapter = async (config) => {
        capturedConfig = config
        return { data: {}, status: 200, statusText: 'OK', headers: {}, config }
      }

      await http.post('/test/resource', { name: 'sample' })
      expect((capturedConfig as unknown as InternalAxiosRequestConfig).headers['X-XSRF-TOKEN']).toBeUndefined()
    })
  })

  describe('RFC 9457 ProblemDetail Response Normalization', () => {
    it('normalizes 401 Unauthorized response with RFC 9457 ProblemDetail', async () => {
      const problemDetail: ProblemDetail = {
        type: 'https://ospysin.dev/errors/unauthorized',
        title: 'Authentication Required',
        status: 401,
        detail: 'Invalid credentials provided',
        instance: '/api/auth/login',
        timestamp: '2026-10-14T12:00:00Z'
      }

      http.defaults.adapter = async () => {
        throw createErrorResponse(401, problemDetail)
      }

      await expect(http.post('/auth/login', {})).rejects.toSatisfy((err: unknown) => {
        expect(err).toBeInstanceOf(ApiError)
        const apiError = err as ApiError
        expect(apiError.status).toBe(401)
        expect(apiError.problem.title).toBe('Authentication Required')
        expect(apiError.problem.detail).toBe('Invalid credentials provided')
        expect(apiError.problem.type).toBe('https://ospysin.dev/errors/unauthorized')
        expect(apiError.problem.instance).toBe('/api/auth/login')
        expect(apiError.problem.timestamp).toBe('2026-10-14T12:00:00Z')
        return true
      })
    })

    it('normalizes 403 Forbidden policy rejection', async () => {
      const problemDetail: ProblemDetail = {
        type: 'https://ospysin.dev/errors/policy-violation',
        title: 'Policy Engine Rejection',
        status: 403,
        detail: 'Target resolves to private network',
        instance: '/api/sessions/test/run'
      }

      http.defaults.adapter = async () => {
        throw createErrorResponse(403, problemDetail)
      }

      await expect(http.post('/sessions/test/run')).rejects.toSatisfy((err: unknown) => {
        expect(err).toBeInstanceOf(ApiError)
        const apiError = err as ApiError
        expect(apiError.status).toBe(403)
        expect(apiError.problem.title).toBe('Policy Engine Rejection')
        expect(apiError.problem.detail).toBe('Target resolves to private network')
        return true
      })
    })

    it('normalizes 422 Unprocessable Entity with invalidParams extension', async () => {
      const problemDetail: ProblemDetail = {
        type: 'https://ospysin.dev/errors/validation-error',
        title: 'Validation Error',
        status: 422,
        detail: 'Input parameters failed validation',
        invalidParams: [
          { name: 'username', reason: 'Must not be blank' },
          { name: 'password', reason: 'Must be at least 8 characters' }
        ]
      }

      http.defaults.adapter = async () => {
        throw createErrorResponse(422, problemDetail)
      }

      await expect(http.post('/auth/login', {})).rejects.toSatisfy((err: unknown) => {
        expect(err).toBeInstanceOf(ApiError)
        const apiError = err as ApiError
        expect(apiError.status).toBe(422)
        expect(apiError.problem.invalidParams).toHaveLength(2)
        expect(apiError.problem.invalidParams?.[0]).toEqual({
          name: 'username',
          reason: 'Must not be blank'
        })
        expect(apiError.problem.invalidParams?.[1]).toEqual({
          name: 'password',
          reason: 'Must be at least 8 characters'
        })
        return true
      })
    })

    it('synthesizes clean ProblemDetail for non-RFC-9457 errors without leaking stack traces', async () => {
      http.defaults.adapter = async () => {
        throw createErrorResponse(500, 'Internal Server Error (raw text or html)')
      }

      await expect(http.get('/health')).rejects.toSatisfy((err: unknown) => {
        expect(err).toBeInstanceOf(ApiError)
        const apiError = err as ApiError
        expect(apiError.status).toBe(500)
        expect(apiError.problem.title).toBe('Network or Server Error')
        expect(apiError.problem.detail).toContain('Request failed with status code 500')
        return true
      })
    })

    it('handles network timeouts (ECONNABORTED) cleanly', async () => {
      http.defaults.adapter = async () => {
        const config = {
          headers: new axios.AxiosHeaders(),
          method: 'get',
          url: '/health'
        } as InternalAxiosRequestConfig
        throw new AxiosError('timeout of 15000ms exceeded', 'ECONNABORTED', config)
      }

      await expect(http.get('/health')).rejects.toSatisfy((err: unknown) => {
        expect(err).toBeInstanceOf(ApiError)
        const apiError = err as ApiError
        expect(apiError.problem.title).toBe('Request Timeout')
        return true
      })
    })

    it('handles unexpected non-Axios exceptions', async () => {
      http.defaults.adapter = async () => {
        throw new Error('Fatal internal runtime crash')
      }

      await expect(http.get('/test')).rejects.toSatisfy((err: unknown) => {
        expect(err).toBeInstanceOf(ApiError)
        const apiError = err as ApiError
        expect(apiError.problem.title).toBe('Unexpected Error')
        expect(apiError.problem.detail).toBe('Fatal internal runtime crash')
        return true
      })
    })
  })

  describe('Unauthorized (401) Callback Dispatcher', () => {
    it('dispatches registered unauthorized callback when 401 is received', async () => {
      const unauthorizedMock = vi.fn()
      setUnauthorizedCallback(unauthorizedMock)
      expect(getUnauthorizedCallback()).toBe(unauthorizedMock)

      http.defaults.adapter = async () => {
        throw createErrorResponse(401, {
          title: 'Unauthorized',
          status: 401,
          detail: 'Session expired'
        })
      }

      await expect(http.get('/auth/me')).rejects.toThrow()
      expect(unauthorizedMock).toHaveBeenCalledTimes(1)
    })

    it('does not dispatch unauthorized callback on 403 or 422 errors', async () => {
      const unauthorizedMock = vi.fn()
      setUnauthorizedCallback(unauthorizedMock)

      http.defaults.adapter = async () => {
        throw createErrorResponse(403, { title: 'Forbidden', status: 403 })
      }

      await expect(http.get('/admin')).rejects.toThrow()
      expect(unauthorizedMock).not.toHaveBeenCalled()
    })
  })
})
