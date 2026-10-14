export interface InvalidParam {
  name: string
  reason: string
}

export interface ProblemDetail {
  type?: string
  title?: string
  status?: number
  detail?: string
  instance?: string
  timestamp?: string
  invalidParams?: InvalidParam[]
}

export interface AuthUser {
  id: string
  username: string
  role: 'ADMIN' | 'AUDITOR'
}

export interface LoginRequest {
  username: string
  password: string
}

export interface HealthResponse {
  status: 'UP' | 'DOWN'
  components: {
    database: string
    ollama: string
  }
}
