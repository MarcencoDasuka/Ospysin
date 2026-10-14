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

export type SessionMode = 'LOCAL' | 'PUBLIC'
export type SessionState = 'ACTIVE' | 'COMPLETED' | 'ABORTED'

export interface CreateSessionRequest {
  targetUrl: string
  mode: SessionMode
  scopeAcknowledged: boolean
  scopeAckVersion: string
}

export interface AuditSession {
  id: string
  targetUrl: string
  mode: SessionMode
  state: SessionState
  scopeAcknowledged: boolean
  scopeAckVersion: string
  scopeAckHash: string
  scopeAckTimestamp: string
  stepCount: number
  findingCount: number
  createdAt: string
  updatedAt: string
}

export interface SessionPageResponse {
  content: AuditSession[]
  page: number
  size: number
  totalElements: number
  totalPages: number
}

export const CANONICAL_SCOPE_ACK_VERSION = '1.0.0'

export const CANONICAL_SCOPE_ACK_STATEMENT =
  'I certify under penalty of law that I own this asset or have received explicit, written authorization to conduct security inspection against the target URL. I understand that all actions are forensically recorded in the local immutable audit log.'

