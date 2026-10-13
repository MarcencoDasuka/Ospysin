# 04. REST API Contracts

## Overview
All client-to-backend communications use JSON over HTTP. Errors conform strictly to the **RFC 9457 Problem Details** standard. Mutating requests are authenticated via `HttpOnly` session cookies with CSRF token verification. Server-Sent Events (SSE) provide real-time updates for asynchronous execution events and LLM advisory responses.

---

## Standard Error Format (RFC 9457)

Errors return `Content-Type: application/problem+json`:

```json
{
  "type": "https://ospysin.dev/errors/policy-violation",
  "title": "Policy Engine Rejection",
  "status": 403,
  "detail": "Target resolves to private network 192.168.1.100 while session is in PUBLIC mode.",
  "instance": "/api/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/tools/http_headers/run",
  "invalidParams": [
    {
      "name": "targetUrl",
      "reason": "Resolves to prohibited special-purpose IP range."
    }
  ],
  "timestamp": "2026-10-09T01:40:00Z"
}
```
*Note: `invalidParams` is an application-specific extension member conforming to RFC 9457 Section 3.2.*

---

## Authentication & Session Security

- **Session Cookie**: `JSESSIONID`, flagged `HttpOnly; SameSite=Strict`. `Secure` attribute is `true` in production/remote modes.
- **CSRF Token**: State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) require the `X-XSRF-TOKEN` header.

### `POST /api/auth/login`
Authenticates the operator.
- **Request Body**:
  ```json
  { "username": "admin", "password": "secure_operator_password" }
  ```
- **Response**: `200 OK` (sets `JSESSIONID` and `XSRF-TOKEN` cookies).
  ```json
  { "id": "uuid", "username": "admin", "role": "ADMIN" }
  ```

### `POST /api/auth/logout`
Invalidates the current session and clears cookies.
- **Response**: `204 No Content`.

### `GET /api/auth/me`
Retrieves currently authenticated user context.
- **Response**: `200 OK`.

---

## API Endpoints

### 1. Tool Catalog
#### `GET /api/tools`
Returns the list of all 15 registered tools across the 3 execution tiers.
- **Response**: `200 OK`
```json
[
  {
    "id": "http_headers",
    "name": "HTTP Headers & Security Check",
    "description": "Inspects response headers, cookies, and evaluates security header posture.",
    "category": "HTTP",
    "executionType": "DIRECT_TARGET_PROBE",
    "riskLevel": "LOW",
    "timeoutSeconds": 10
  },
  {
    "id": "dns_lookup",
    "name": "DNS Record Enumeration",
    "description": "Queries A, AAAA, CNAME, MX, TXT, and NS records for target domain.",
    "category": "DNS",
    "executionType": "THIRD_PARTY_RECON",
    "riskLevel": "LOW",
    "timeoutSeconds": 10
  },
  {
    "id": "security_headers_score",
    "name": "Security Headers Evaluation Score",
    "description": "Purely offline analysis tool evaluating headers previously captured by http_headers.",
    "category": "ANALYSIS",
    "executionType": "OFFLINE_ANALYSIS",
    "riskLevel": "LOW",
    "timeoutSeconds": 1
  }
]
```

---

### 2. Session Management
#### `GET /api/sessions`
Retrieves a paginated list of audit sessions for Screen 1 (Session List).
- **Query Parameters**: `page` (integer, default 0), `size` (integer, default 20)
- **Response**: `200 OK`
```json
{
  "content": [
    {
      "id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "targetUrl": "https://example.com",
      "mode": "PUBLIC",
      "state": "ACTIVE",
      "stepCount": 4,
      "findingCount": 2,
      "createdAt": "2026-10-09T01:20:00Z"
    }
  ],
  "totalElements": 1,
  "totalPages": 1
}
```

#### `POST /api/sessions`
Initializes a new audit session for a target URL.
- **Request Body**:
```json
{
  "targetUrl": "https://example.com",
  "mode": "PUBLIC",
  "scopeAcknowledged": true,
  "scopeAckVersion": "1.0.0"
}
```
- **Response**: `201 Created`
```json
{
  "id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "targetUrl": "https://example.com",
  "mode": "PUBLIC",
  "state": "ACTIVE",
  "scopeAcknowledged": true,
  "scopeAckVersion": "1.0.0",
  "scopeAckHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "scopeAckTimestamp": "2026-10-09T01:40:00Z",
  "createdAt": "2026-10-09T01:40:00Z"
}
```
- **Status Codes**:
  - `201 Created`: Session created and active.
  - `400 Bad Request`: Malformed request syntax.
  - `422 Unprocessable Entity`: Validation failure on `targetUrl` or parameters (`invalidParams`).
  - `403 Forbidden`: Scope policy violation (e.g. special-purpose IP in PUBLIC mode) or unacknowledged scope.

#### `GET /api/sessions/{id}`
Retrieves session metadata, current state, and summary statistics.
- **Response**: `200 OK`.

#### `POST /api/sessions/{id}/complete`
Transitions session from `ACTIVE` to `COMPLETED`.
- **Response**: `200 OK` (or `409 Conflict` if any executions are `RUNNING` or `PENDING`).

#### `POST /api/sessions/{id}/abort`
Terminates session immediately. Running network sockets are interrupted without persisting partial output to `tool_results`; pending executions transition to `CANCELLED`; session transitions to `ABORTED`.
- **Response**: `200 OK`.

---

### 3. Tool Execution & Queue
#### `POST /api/sessions/{id}/tools/{toolId}/run`
Enqueues a tool execution task.
- **Request Body** (optional arguments or offline step reference):
```json
{
  "customPort": null,
  "followRedirects": false,
  "stepId": null
}
```
- **Response**: `202 Accepted`
  - **Headers**: `Location: /api/sessions/{id}/steps/c4ca4238-a0b9-3382-8dcc-509a6f75849b`
  - **Body**:
```json
{
  "executionId": "c4ca4238-a0b9-3382-8dcc-509a6f75849b",
  "toolId": "http_headers",
  "status": "PENDING",
  "enqueuedAt": "2026-10-09T01:41:00Z"
}
```
- **Status Codes**:
  - `202 Accepted`: Enqueued into background execution queue.
  - `400 Bad Request`: Malformed JSON or unknown tool ID.
  - `422 Unprocessable Entity`: Parameter validation error with RFC 9457 `invalidParams`.
  - `403 Forbidden`: Policy engine rejection or unacknowledged scope.
  - `409 Conflict`: An identical tool execution is already `PENDING` or `RUNNING`.

#### `GET /api/sessions/{id}/steps`
Lists all tool steps and their execution states in chronological order.
- **Response**: `200 OK`.

#### `GET /api/sessions/{id}/steps/{stepId}`
Fetches the full result payload of an individual execution.
- **Response**: `200 OK`.

---

### 4. Findings & Evidence Management
#### `POST /api/sessions/{id}/findings`
Creates an auditor finding from an observation or manual inspection.
- **Request Body**:
```json
{
  "title": "Missing Content-Security-Policy",
  "description": "Target server omits CSP header, allowing script injection.",
  "severity": "MEDIUM",
  "confidence": "TENTATIVE",
  "status": "POTENTIAL",
  "observationId": "uuid-of-observation-optional"
}
```
- **Response**: `201 Created`.

#### `GET /api/sessions/{id}/findings`
Lists all findings for a session.
- **Response**: `200 OK`.

#### `PATCH /api/findings/{id}`
Updates finding fields (severity, remediation, status `UNDER_REVIEW`, `CONFIRMED`).
- **Response**: `200 OK`.

#### `POST /api/findings/{id}/reject`
Marks a finding as a false positive with an auditable explanation.
- **Request Body**:
```json
{
  "reason": "Verified that endpoint is protected by external WAF and mutual TLS."
}
```
- **Response**: `200 OK` (updates status to `REJECTED`, logs audit event).

#### `POST /api/findings/{id}/evidence`
Links an immutable snippet from `tool_results` to a finding.
- **Request Body**:
```json
{
  "resultId": "uuid-of-tool-result",
  "snippet": "HTTP/1.1 200 OK\r\nServer: nginx..."
}
```
- **Response**: `201 Created`.

---

### 5. Real-Time Event Stream (SSE)
#### `GET /api/sessions/{id}/events`
SSE stream pushing updates to the UI.
- **Headers**: `Accept: text/event-stream`
- **Stream Event Types**:
  - `step_queued`: `{ "executionId": "...", "toolId": "...", "status": "PENDING" }`
  - `step_started`: `{ "executionId": "...", "toolId": "..." }`
  - `step_finished`: `{ "executionId": "...", "status": "COMPLETED" }`
  - `step_failed`: `{ "executionId": "...", "status": "FAILED", "failureReason": "..." }`
  - `llm_comment_ready`: `{ "comment": "...", "suggestedTool": "tls_info", "suggestedReason": "..." }`
  - `llm_chat_reply`: `{ "reply": "..." }`
  - `policy_alert`: `{ "level": "WARN", "message": "..." }`
  - `session_completed`: `{ "sessionId": "..." }`
  - `session_aborted`: `{ "sessionId": "..." }`

---

### 6. Local LLM Advisory
#### `POST /api/sessions/{id}/llm/comment`
Requests on-demand re-generation of commentary for a step.
- **Request Body**: `{ "stepId": "uuid" }`
- **Response**: `202 Accepted` (dispatches background task; result pushed via SSE `llm_comment_ready`).

#### `POST /api/sessions/{id}/llm/chat`
Ad-hoc tactical sounding board grounded in session context.
- **Request Body**: `{ "message": "Why is this header significant?" }`
- **Response**: `202 Accepted` `{ "status": "PENDING", "message": "Chat query enqueued" }` (dispatches background task; result delivered asynchronously via SSE `llm_chat_reply`).

---

### 7. Audit Report
#### `GET /api/sessions/{id}/report`
Exports aggregated session metadata, confirmed findings (excluding `REJECTED`), evidence, and execution history.
- **Response**: `200 OK`.

---

### 8. System Health
#### `GET /api/health`
Retrieves service health status and component connectivity.
- **Response**: `200 OK`
```json
{
  "status": "UP",
  "components": {
    "database": "UP",
    "ollama": "UP"
  }
}
```
