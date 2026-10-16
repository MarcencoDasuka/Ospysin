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

export type ExecutionType = 'THIRD_PARTY_RECON' | 'DIRECT_TARGET_PROBE' | 'OFFLINE_ANALYSIS'
export type ExecutionStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED'
export type SeverityHeuristic = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH'

export interface ToolMetadata {
  id: string
  name: string
  category: string
  executionType: ExecutionType
  description: string
  inputSchema: Record<string, unknown>
}

export interface ToolRunAcceptedResponse {
  executionId: string
  sessionId: string
  toolId: string
  status: ExecutionStatus
  enqueuedAt: string
}

export interface StepSummaryResponse {
  executionId: string
  toolId: string
  status: ExecutionStatus
  durationMs: number | null
  observationCount: number
  startedAt: string | null
  endedAt: string | null
}

export interface ObservationDto {
  id: string
  category: string
  description: string
  severityHeuristic: SeverityHeuristic
  detectedAt: string
}

export interface StepDetailResponse {
  executionId: string
  resultId?: string | null
  toolId: string
  status: ExecutionStatus
  durationMs: number | null
  failureReason: string | null
  rawOutput: string | null
  parsedData: Record<string, unknown>
  score: number | null
  observations: ObservationDto[]
  startedAt: string | null
  endedAt: string | null
}

export type StepDetail = StepDetailResponse


export interface ParsedCookieView {
  name: string
  secure: boolean
  httpOnly: boolean
  sameSite: string | null
  path: string | null
  domain: string | null
}

export interface RedirectHopView {
  hop?: number
  fromUrl?: string
  toUrl?: string
  statusCode?: number
}

export type SseConnectionState = 'DISCONNECTED' | 'CONNECTING' | 'CONNECTED' | 'ERROR'
export type SseLogLevel = 'INFO' | 'SUCCESS' | 'WARN' | 'ERROR'

export interface WorkspaceSseEvent {
  id: string
  timestamp: string
  eventName: string
  level: SseLogLevel
  message: string
  payload: Record<string, unknown>
}

export interface LlmCommentRequest {
  stepId: string
}

export interface LlmChatRequest {
  message: string
}

export interface LlmAsyncAcceptedResponse {
  status: string
  message: string
}

export interface LlmCommentPayload {
  stepId: string
  toolId?: string
  comment: string
  suggestedTool?: string | null
  suggestedReason?: string | null
  timestamp?: string
}

export interface LlmChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: string
}

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type FindingConfidence = 'CERTAIN' | 'FIRM' | 'TENTATIVE'
export type FindingStatus = 'OPEN' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'REJECTED'

export interface EvidenceItem {
  id: string
  findingId: string
  resultId: string
  executionId: string
  toolId: string
  snippet: string
  createdAt: string
}

export interface Finding {
  id: string
  sessionId: string
  observationId: string | null
  title: string
  description: string
  severity: FindingSeverity
  confidence: FindingConfidence
  status: FindingStatus
  rejectionReason: string | null
  remediation: string | null
  evidence: EvidenceItem[]
  createdAt: string
  updatedAt: string
}

export interface CreateFindingRequest {
  observationId?: string | null
  title: string
  description: string
  severity: FindingSeverity
  confidence?: FindingConfidence
  remediation?: string | null
}

export interface UpdateFindingRequest {
  title?: string
  description?: string
  severity?: FindingSeverity
  confidence?: FindingConfidence
  status?: FindingStatus
  rejectionReason?: string | null
  remediation?: string | null
}

export interface CreateEvidenceRequest {
  resultId: string
  snippet: string
}

export interface SessionObservation {
  id: string
  executionId: string
  resultId: string
  toolId: string
  category: string
  description: string
  severityHeuristic: SeverityHeuristic
  detectedAt: string
}


