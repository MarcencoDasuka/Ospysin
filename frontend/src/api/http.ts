import axios, { type AxiosInstance } from 'axios'
import type { ProblemDetail } from './types'

export class ApiError extends Error {
  public readonly status: number
  public readonly problem: ProblemDetail

  constructor(problem: ProblemDetail) {
    super(problem.detail || problem.title || 'An API error occurred')
    this.name = 'ApiError'
    this.status = problem.status ?? 500
    this.problem = problem
    Object.setPrototypeOf(this, ApiError.prototype)
  }
}

export type UnauthorizedCallback = () => void

let unauthorizedCallback: UnauthorizedCallback | null = null

export function setUnauthorizedCallback(callback: UnauthorizedCallback | null): void {
  unauthorizedCallback = callback
}

export function getUnauthorizedCallback(): UnauthorizedCallback | null {
  return unauthorizedCallback
}

export function getCookie(name: string): string | null {
  if (typeof document === 'undefined' || !document.cookie) {
    return null
  }
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = document.cookie.match(new RegExp('(?:^|;\\s*)' + escapedName + '=([^;]*)'))
  if (!match) {
    return null
  }
  try {
    return decodeURIComponent(match[1])
  } catch {
    return match[1]
  }
}

export const http: AxiosInstance = axios.create({
  baseURL: '/api',
  withCredentials: true,
  timeout: 15000,
  xsrfCookieName: 'XSRF-TOKEN',
  xsrfHeaderName: 'X-XSRF-TOKEN',
  headers: {
    'Accept': 'application/json, application/problem+json',
    'Content-Type': 'application/json'
  }
})

// Interceptor ensuring X-XSRF-TOKEN header is attached from document.cookie on mutating requests
http.interceptors.request.use((config) => {
  const method = config.method?.toUpperCase()
  if (method && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const token = getCookie('XSRF-TOKEN')
    if (token) {
      config.headers = config.headers || {}
      config.headers['X-XSRF-TOKEN'] = token
    }
  }
  return config
})

// Interceptor normalizing RFC 9457 errors and dispatching 401 callback
http.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status ?? 500
      let problem: ProblemDetail

      if (error.response?.data && typeof error.response.data === 'object') {
        const data = error.response.data as Record<string, unknown>
        problem = {
          type: typeof data.type === 'string' ? data.type : undefined,
          title: typeof data.title === 'string' ? data.title : (status === 401 ? 'Unauthorized' : 'API Error'),
          status: typeof data.status === 'number' ? data.status : status,
          detail: typeof data.detail === 'string' ? data.detail : error.message,
          instance: typeof data.instance === 'string' ? data.instance : undefined,
          timestamp: typeof data.timestamp === 'string' ? data.timestamp : undefined,
          invalidParams: Array.isArray(data.invalidParams) ? data.invalidParams : undefined
        }
      } else {
        problem = {
          title: status === 401 ? 'Unauthorized' : (error.code === 'ECONNABORTED' ? 'Request Timeout' : 'Network or Server Error'),
          status,
          detail: error.message || 'An unexpected error occurred while communicating with the server'
        }
      }

      if (status === 401 && unauthorizedCallback) {
        try {
          unauthorizedCallback()
        } catch {
          // Prevent handler failure from swallowing the normalized ApiError
        }
      }

      return Promise.reject(new ApiError(problem))
    }

    const fallbackProblem: ProblemDetail = {
      title: 'Unexpected Error',
      status: 500,
      detail: error instanceof Error ? error.message : 'Unknown internal error'
    }
    return Promise.reject(new ApiError(fallbackProblem))
  }
)

export default http
