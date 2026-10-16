import { test, expect, type Page, type Route } from '@playwright/test'

interface SessionData {
  id: string
  targetUrl: string
  mode: 'PUBLIC' | 'LOCAL'
  state: 'ACTIVE' | 'COMPLETED' | 'ABORTED'
  stepCount: number
  findingCount: number
  createdAt: string
  updatedAt: string
}

interface FindingData {
  id: string
  sessionId: string
  observationId: string | null
  title: string
  description: string
  severity: string
  confidence: string
  status: 'OPEN' | 'CONFIRMED' | 'REJECTED' | 'FALSE_POSITIVE'
  remediation: string | null
  rejectionReason: string | null
  evidence: Array<{
    id: string
    findingId: string
    resultId: string
    toolId: string
    snippet: string
    createdAt: string
  }>
  createdAt: string
  updatedAt: string
}

const CANONICAL_TOOLS = [
  {
    id: 'dns_lookup',
    name: 'DNS Record Enumeration',
    category: 'DNS',
    executionType: 'THIRD_PARTY_RECON',
    description: 'Queries primary resource records (A, AAAA, MX, TXT, NS, CNAME) for the target domain.',
    inputSchema: { recordTypes: ['A', 'AAAA', 'MX', 'TXT', 'NS'] }
  },
  {
    id: 'whois_lookup',
    name: 'WHOIS / RDAP Registration',
    category: 'WHOIS',
    executionType: 'THIRD_PARTY_RECON',
    description: 'Queries authoritative WHOIS / RDAP registration directories.',
    inputSchema: { referralDepth: 1 }
  },
  {
    id: 'tls_info',
    name: 'TLS/SSL Handshake & Cipher Suite',
    category: 'TLS',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Establishes a direct TLS handshake to inspect peer certificates and cipher suites.',
    inputSchema: { port: 443 }
  },
  {
    id: 'http_headers',
    name: 'HTTP Headers & Cookies',
    category: 'HTTP',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Fetches and analyzes HTTP response headers, cookies, and server banners.',
    inputSchema: { customPort: null, followRedirects: false }
  },
  {
    id: 'robots_txt',
    name: 'Robots.txt Disallow Inspection',
    category: 'RECON',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Retrieves /robots.txt and parses user-agents, disallow rules, and declared sitemaps.',
    inputSchema: {}
  },
  {
    id: 'sitemap_xml',
    name: 'Sitemap Structure Parser',
    category: 'RECON',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Fetches and parses sitemap.xml to enumerate endpoints and sensitive paths.',
    inputSchema: { customPath: '/sitemap.xml', maxUrls: 500 }
  },
  {
    id: 'extract_links',
    name: 'Internal & External Link Harvester',
    category: 'CONTENT',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Retrieves landing page HTML and parses anchor links into internal and external URLs.',
    inputSchema: { maxLinks: 200 }
  },
  {
    id: 'extract_js_urls',
    name: 'JavaScript Asset Harvester',
    category: 'CONTENT',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Discovers and parses script tags to catalog loaded client-side JavaScript bundles.',
    inputSchema: {}
  },
  {
    id: 'tech_detect',
    name: 'Technology Fingerprint Heuristics',
    category: 'RECON',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Probes responses to identify underlying web servers, frameworks, and CMS platforms.',
    inputSchema: {}
  },
  {
    id: 'sensitive_files_check',
    name: 'Exposed Sensitive Files & Endpoints',
    category: 'SECURITY',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Probes target server directly for known sensitive files, backup archives, and debug endpoints.',
    inputSchema: { customPaths: [], stopOnFirstExposed: false }
  },
  {
    id: 'js_secrets_scanner',
    name: 'JS Bundle Secrets Scanner',
    category: 'SECURITY',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Scans client-side JavaScript bundles to detect leaked API keys, tokens, and credentials.',
    inputSchema: { jsUrls: [], maxFiles: 10 }
  },
  {
    id: 'cors_misconfig_check',
    name: 'CORS Misconfiguration & Origin Probe',
    category: 'SECURITY',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Tests CORS implementation against arbitrary and null origins with credentials.',
    inputSchema: { customOrigins: [] }
  },
  {
    id: 'subdomain_takeover_check',
    name: 'Subdomain Takeover & Dangling DNS',
    category: 'DNS',
    executionType: 'DIRECT_TARGET_PROBE',
    description: 'Inspects CNAME records for dangling pointers to unclaimed third-party cloud services.',
    inputSchema: { subdomains: [] }
  },
  {
    id: 'security_headers_score',
    name: 'Security Headers Evaluation Score',
    category: 'ANALYSIS',
    executionType: 'OFFLINE_ANALYSIS',
    description: 'Purely offline analysis tool evaluating headers previously captured by http_headers.',
    inputSchema: { stepId: '' }
  },
  {
    id: 'cve_matcher',
    name: 'Offline CVE Vulnerability Matcher',
    category: 'ANALYSIS',
    executionType: 'OFFLINE_ANALYSIS',
    description: 'Offline correlation of detected technologies and version strings against CVE catalog.',
    inputSchema: { stepId: '' }
  }
]

class MockBackend {
  public isAuthenticated = false
  public sessions: SessionData[] = []
  public steps: any[] = []
  public findings: FindingData[] = []

  constructor() {
    this.reset()
  }

  reset() {
    this.isAuthenticated = false
    this.sessions = []
    this.steps = []
    this.findings = []
  }

  async setupRoutes(page: Page) {
    // Inject MockEventSource into window before any script loads
    await page.addInitScript(() => {
      class MockEventSource {
        static instances: MockEventSource[] = []
        public url: string
        public listeners: Record<string, Function[]> = {}
        public readyState = 0
        public onmessage: ((e: MessageEvent) => void) | null = null

        constructor(url: string) {
          this.url = url
          MockEventSource.instances.push(this)
          setTimeout(() => {
            this.readyState = 1
            this.dispatchEvent('connected', { data: JSON.stringify({ sessionId: 'sess-test-01' }) })
          }, 30)
        }

        addEventListener(type: string, listener: Function) {
          if (!this.listeners[type]) this.listeners[type] = []
          this.listeners[type].push(listener)
        }

        removeEventListener(type: string, listener: Function) {
          if (this.listeners[type]) {
            this.listeners[type] = this.listeners[type].filter((l) => l !== listener)
          }
        }

        dispatchEvent(type: string, eventInitDict?: any) {
          const event = new MessageEvent(type, {
            data:
              typeof eventInitDict?.data === 'string'
                ? eventInitDict.data
                : JSON.stringify(eventInitDict || {})
          })
          if (this.listeners[type]) {
            this.listeners[type].forEach((l) => l(event))
          }
          if (type === 'message' && this.onmessage) {
            this.onmessage(event)
          }
        }

        close() {
          this.readyState = 2
          const idx = MockEventSource.instances.indexOf(this)
          if (idx !== -1) MockEventSource.instances.splice(idx, 1)
        }
      }

      // @ts-ignore
      window.EventSource = MockEventSource
      // @ts-ignore
      window.__dispatchSse = (type: string, data: any) => {
        MockEventSource.instances.forEach((es) =>
          es.dispatchEvent(type, { data: JSON.stringify(data) })
        )
      }
    })

    // Intercept all /api/ calls
    await page.route('**/api/**', async (route: Route) => {
      const request = route.request()
      const url = new URL(request.url())
      const path = url.pathname
      const method = request.method()

      // 1. Auth Me
      if (path === '/api/auth/me' && method === 'GET') {
        if (!this.isAuthenticated) {
          return route.fulfill({
            status: 401,
            contentType: 'application/problem+json',
            body: JSON.stringify({
              type: 'about:blank',
              title: 'Unauthorized',
              status: 401,
              detail: 'Session expired or operator not authenticated.'
            })
          })
        }
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ username: 'admin', role: 'ROLE_ADMIN' })
        })
      }

      // 2. Auth Login
      if (path === '/api/auth/login' && method === 'POST') {
        const body = request.postDataJSON()
        if (body.username === 'admin' && body.password === 'admin_secret_locally') {
          this.isAuthenticated = true
          return route.fulfill({
            status: 200,
            contentType: 'application/json',
            headers: { 'Set-Cookie': 'JSESSIONID=mock-session; Path=/' },
            body: JSON.stringify({ username: 'admin', role: 'ROLE_ADMIN' })
          })
        }
        return route.fulfill({
          status: 401,
          contentType: 'application/problem+json',
          body: JSON.stringify({
            type: 'about:blank',
            title: 'Authentication Failed',
            status: 401,
            detail: 'Invalid credentials provided.',
            invalidParams: []
          })
        })
      }

      // 3. Auth Logout
      if (path === '/api/auth/logout' && method === 'POST') {
        this.isAuthenticated = false
        return route.fulfill({ status: 204 })
      }

      // 4. Health Probe
      if (path === '/api/health' && method === 'GET') {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            status: 'UP',
            components: {
              database: 'UP',
              ollama: 'UP'
            },
            model: 'hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M'
          })
        })
      }

      // 5. Tool Catalog
      if (path === '/api/tools' && method === 'GET') {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(CANONICAL_TOOLS)
        })
      }

      // 6. Session Creation & List
      if (path === '/api/sessions' && method === 'GET') {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            content: this.sessions,
            totalElements: this.sessions.length,
            totalPages: 1,
            size: 20,
            number: 0
          })
        })
      }

      if (path === '/api/sessions' && method === 'POST') {
        const body = request.postDataJSON()
        const newSession: SessionData = {
          id: 'sess-test-01',
          targetUrl: body.targetUrl,
          mode: body.mode || 'PUBLIC',
          state: 'ACTIVE',
          stepCount: 0,
          findingCount: 0,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
        this.sessions = [newSession, ...this.sessions]
        return route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify(newSession)
        })
      }

      // 7. Session Details
      if (path === '/api/sessions/sess-test-01' && method === 'GET') {
        const s = this.sessions.find((sess) => sess.id === 'sess-test-01') || {
          id: 'sess-test-01',
          targetUrl: 'http://localhost:8080',
          mode: 'LOCAL',
          state: 'ACTIVE',
          stepCount: this.steps.length,
          findingCount: this.findings.length,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(s)
        })
      }

      // 8. Session Complete
      if (path === '/api/sessions/sess-test-01/complete' && method === 'POST') {
        const s = this.sessions.find((sess) => sess.id === 'sess-test-01')
        if (s) s.state = 'COMPLETED'
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(s)
        })
      }

      // 9. Session Steps List
      if (path === '/api/sessions/sess-test-01/steps' && method === 'GET') {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(this.steps)
        })
      }

      // 10. Run Tool: http_headers
      if (path === '/api/sessions/sess-test-01/tools/http_headers/run' && method === 'POST') {
        const accepted = {
          executionId: 'exec-http-01',
          sessionId: 'sess-test-01',
          toolId: 'http_headers',
          status: 'PENDING',
          enqueuedAt: new Date().toISOString()
        }
        this.steps = [
          {
            executionId: 'exec-http-01',
            toolId: 'http_headers',
            status: 'COMPLETED',
            durationMs: 42,
            observationCount: 2,
            startedAt: new Date().toISOString(),
            endedAt: new Date().toISOString()
          }
        ]
        return route.fulfill({
          status: 202,
          contentType: 'application/json',
          body: JSON.stringify(accepted)
        })
      }

      // 11. Step Details: exec-http-01
      if (path === '/api/sessions/sess-test-01/steps/exec-http-01' && method === 'GET') {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            executionId: 'exec-http-01',
            toolId: 'http_headers',
            status: 'COMPLETED',
            durationMs: 42,
            failureReason: null,
            rawOutput:
              'HTTP/1.1 200 OK\r\nDate: Fri, 16 Oct 2026 12:00:00 GMT\r\nServer: nginx/1.27.0\r\nContent-Type: text/html\r\nSet-Cookie: session=xyz987; Path=/; HttpOnly\r\n\r\n<!DOCTYPE html><html><body>Secure Target</body></html>',
            parsedData: {
              statusCode: 200,
              httpVersion: 'HTTP/1.1',
              finalUrl: 'http://localhost:8080',
              serverBanner: 'nginx/1.27.0',
              headers: {
                Server: 'nginx/1.27.0',
                'Content-Type': 'text/html',
                Date: 'Fri, 16 Oct 2026 12:00:00 GMT'
              },
              cookies: [
                {
                  name: 'session',
                  value: 'xyz987',
                  secure: false,
                  httpOnly: true,
                  sameSite: null,
                  path: '/'
                }
              ],
              redirectChain: []
            },
            score: null,
            observations: [
              {
                id: 'obs-http-01',
                category: 'MISSING_HEADER',
                description: 'Missing Content-Security-Policy header',
                severityHeuristic: 'MEDIUM'
              },
              {
                id: 'obs-http-02',
                category: 'INSECURE_COOKIE',
                description: "Cookie 'session' missing Secure flag",
                severityHeuristic: 'LOW'
              }
            ],
            resultId: 'res-http-01',
            startedAt: new Date().toISOString(),
            endedAt: new Date().toISOString()
          })
        })
      }

      // 12. Tactical Chat Query
      if (path === '/api/sessions/sess-test-01/llm/chat' && method === 'POST') {
        return route.fulfill({
          status: 202,
          contentType: 'application/json',
          body: JSON.stringify({ status: 'ACCEPTED' })
        })
      }

      // 13. Findings CRUD & Evidence
      if (path === '/api/sessions/sess-test-01/findings' && method === 'GET') {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(this.findings)
        })
      }

      if (path === '/api/sessions/sess-test-01/findings' && method === 'POST') {
        const fData = request.postDataJSON()
        const findingId = fData.title.includes('False Positive') ? 'finding-02' : 'finding-01'
        const newFinding: FindingData = {
          id: findingId,
          sessionId: 'sess-test-01',
          observationId: fData.observationId || null,
          title: fData.title,
          description: fData.description,
          severity: fData.severity || 'MEDIUM',
          confidence: fData.confidence || 'FIRM',
          status: 'OPEN',
          remediation: fData.remediation || null,
          rejectionReason: null,
          evidence: [],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
        this.findings.push(newFinding)
        return route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify(newFinding)
        })
      }

      if (
        path.startsWith('/api/sessions/sess-test-01/findings/') &&
        !path.includes('/evidence') &&
        (method === 'PATCH' || method === 'PUT')
      ) {
        const findingId = path.split('/').pop()
        const updateData = request.postDataJSON()
        const target = this.findings.find((f) => f.id === findingId)
        if (target) {
          if (updateData.status) target.status = updateData.status
          if (updateData.rejectionReason) target.rejectionReason = updateData.rejectionReason
          target.updatedAt = new Date().toISOString()
        }
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(target)
        })
      }

      if (path.includes('/evidence') && method === 'POST') {
        const evidenceData = request.postDataJSON()
        const evItem = {
          id: 'ev-01',
          findingId: 'finding-01',
          resultId: evidenceData.resultId,
          toolId: 'http_headers',
          snippet: evidenceData.snippet,
          createdAt: new Date().toISOString()
        }
        const targetFinding = this.findings.find((f) => f.id === 'finding-01')
        if (targetFinding) {
          if (!targetFinding.evidence) targetFinding.evidence = []
          targetFinding.evidence.push(evItem)
        }
        return route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify(evItem)
        })
      }

      // 14. Standalone Report View HTML
      if (path === '/api/sessions/sess-test-01/report' && method === 'GET') {
        const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Ospysin Security Audit Report - sess-test-01</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; }
    .executive-summary { border-left: 4px solid #0891b2; padding-left: 1rem; margin-bottom: 2rem; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
    .badge-medium { background: #fef3c7; color: #92400e; }
    .evidence-block { background: #f8fafc; border: 1px solid #e2e8f0; padding: 1rem; border-radius: 4px; }
    .appendix { border-top: 2px dashed #cbd5e1; margin-top: 3rem; padding-top: 1rem; }
  </style>
</head>
<body>
  <h1>Ospysin Security Audit Report</h1>
  <div class="executive-summary">
    <h2>Executive Summary</h2>
    <p>Target Scope: <strong>http://localhost:8080</strong></p>
    <p>Audit Mode: <strong>LOCAL</strong></p>
  </div>

  <h2>Section 4: Confirmed Findings</h2>
  <div class="finding-item">
    <h3>[MISSING_HEADER] Missing Content-Security-Policy header</h3>
    <span class="badge badge-medium">MEDIUM</span>
    <p>Target web server omits defensive Content-Security-Policy directives.</p>
    <div class="evidence-block">
      <h4>Evidence Snippet:</h4>
      <pre>Server: nginx/1.27.0\nMissing CSP</pre>
    </div>
  </div>

  <div class="appendix">
    <h2>Section 5: Rejected Findings Appendix</h2>
    <div class="rejected-finding-item">
      <h3>False Positive CVE-2024-9999</h3>
      <p>Suspected vulnerability debunked by source audit.</p>
      <p><strong>Rejection Reason:</strong> Verified not exploitable in staging environment</p>
    </div>
  </div>
</body>
</html>`
        return route.fulfill({
          status: 200,
          contentType: 'text/html; charset=utf-8',
          body: html
        })
      }

      // Default fallback
      return route.continue()
    })
  }
}

test.describe('Ospysin Vertical Operator Workflow E2E Suite', () => {
  let backend: MockBackend

  test.beforeEach(async ({ page }) => {
    backend = new MockBackend()
    await backend.setupRoutes(page)
  })

  test('Test 1 — Authentication & Route Guard Flow', async ({ page }) => {
    // 1. Unauthenticated visit to root '/' MUST redirect to '/login'
    await page.goto('/')
    await expect(page).toHaveURL(/.*\/login/)

    // 2. Submit invalid credentials -> displays RFC 9457 error callout
    await page.locator('[data-testid="username-input"]').fill('wrong_operator')
    await page.locator('[data-testid="password-input"]').fill('invalid_secret')
    await page.locator('[data-testid="signin-button"]').click()

    const errorCallout = page.locator('[data-testid="error-callout"]')
    await expect(errorCallout).toBeVisible()
    await expect(errorCallout).toContainText('Invalid credentials provided.')

    // 3. Submit valid credentials -> transitions to '/' (Screen 1) and displays [Ollama: READY] health badge
    await page.locator('[data-testid="username-input"]').fill('admin')
    await page.locator('[data-testid="password-input"]').fill('admin_secret_locally')
    await page.locator('[data-testid="signin-button"]').click()

    await expect(page).toHaveURL('http://127.0.0.1:4173/')
    const healthBadge = page.locator('[data-testid="health-badge"]')
    await expect(healthBadge).toBeVisible()
    await expect(healthBadge).toContainText('[Ollama: READY]')
  })

  test('Test 2 — Session Creation & Mandatory Scope Attestation Gate', async ({ page }) => {
    // Authenticate operator
    backend.isAuthenticated = true
    await page.goto('/')
    await expect(page).toHaveURL('http://127.0.0.1:4173/')

    // 1. Open New Session Modal
    const newSessionBtn = page.locator('[data-testid="new-session-button"]')
    await expect(newSessionBtn).toBeVisible()
    await newSessionBtn.click()

    const targetUrlInput = page.locator('[data-testid="target-url-input"]')
    const scopeCheckbox = page.locator('[data-testid="scope-ack-checkbox"]')
    const submitBtn = page.locator('[data-testid="submit-session-button"]')

    await expect(targetUrlInput).toBeVisible()

    // 2. Attestation Gate: Submit remains disabled until URL entered AND checkbox checked
    await expect(submitBtn).toBeDisabled()

    // Enter target URL only -> still disabled
    await targetUrlInput.fill('http://localhost:8080')
    await expect(submitBtn).toBeDisabled()

    // Check scope attestation -> submit button becomes enabled
    await scopeCheckbox.check()
    await expect(submitBtn).toBeEnabled()

    // 3. Select LOCAL mode radio card
    const localModeRadio = page.locator('[data-testid="mode-local-radio"]')
    await localModeRadio.check()

    // 4. Submit session form -> navigates to Session Workspace View
    await submitBtn.click()
    await expect(page).toHaveURL(/.*\/sessions\/sess-test-01/)
  })

  test('Test 3 — Complete 4-Panel Workspace, Tool Execution, AI Advisor, Findings Curation & Standalone Report Export', async ({
    page
  }) => {
    // Seed authenticated session in backend
    backend.isAuthenticated = true
    backend.sessions = [
      {
        id: 'sess-test-01',
        targetUrl: 'http://localhost:8080',
        mode: 'LOCAL',
        state: 'ACTIVE',
        stepCount: 0,
        findingCount: 0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }
    ]

    await page.goto('/sessions/sess-test-01')
    await expect(page.locator('[data-testid="workspace-target-url"]')).toHaveText('http://localhost:8080')
    await expect(page.locator('[data-testid="workspace-mode-badge"]')).toHaveText('LOCAL')
    await expect(page.locator('[data-testid="workspace-state-badge"]')).toHaveText('ACTIVE')

    // 1. Verify all 15 tools are rendered across the 3 canonical tiers in the Left Panel
    for (const tool of CANONICAL_TOOLS) {
      const toolCard = page.locator(`[data-testid="tool-card-${tool.id}"]`)
      await expect(toolCard).toBeVisible()
      const runBtn = page.locator(`[data-testid="run-tool-${tool.id}"]`)
      await expect(runBtn).toBeVisible()
    }

    // 2. Trigger http_headers tool execution
    const runHttpBtn = page.locator('[data-testid="run-tool-http_headers"]')
    const [runResponse] = await Promise.all([
      page.waitForResponse((res) => res.url().includes('/tools/http_headers/run')),
      runHttpBtn.click()
    ])
    expect(runResponse.status()).toBe(202)

    // Simulate backend worker emitting step_finished & llm_comment_ready over SSE
    await page.evaluate(() => {
      // @ts-ignore
      window.__dispatchSse('step_finished', {
        executionId: 'exec-http-01',
        sessionId: 'sess-test-01',
        toolId: 'http_headers',
        durationMs: 42,
        observationCount: 2
      })
      // @ts-ignore
      window.__dispatchSse('llm_comment_ready', {
        stepId: 'exec-http-01',
        toolId: 'http_headers',
        comment:
          'Target web server is running nginx/1.27.0. Security headers are severely deficient; CSP is absent, exposing the application to cross-site scripting attacks.',
        suggestedTool: 'tech_detect',
        suggestedReason: 'Fingerprint web frameworks and libraries to check for known CVEs.'
      })
    })

    // 3. Verify step timeline status transitions to COMPLETED
    const stepTab = page.locator('[data-testid="step-tab-exec-http-01"]')
    await expect(stepTab).toBeVisible()
    await expect(stepTab).toContainText('COMPLETED')

    // 4. Center Panel: verify parsed headers table, cookies, and automated observations
    const headersTable = page.locator('[data-testid="http-headers-table"]')
    await expect(headersTable).toBeVisible()
    await expect(headersTable).toContainText('Server')
    await expect(headersTable).toContainText('nginx/1.27.0')

    const cookiesTable = page.locator('[data-testid="http-cookies-table"]')
    await expect(cookiesTable).toBeVisible()
    await expect(cookiesTable).toContainText('session')

    const observationsList = page.locator('[data-testid="step-observations-list"]')
    await expect(observationsList).toBeVisible()
    await expect(observationsList).toContainText('Missing Content-Security-Policy header')

    // 5. Right Panel: Verify AI Advisor commentary, suggested tool, and tactical chat
    const advisorCard = page.locator('[data-testid="advisor-comment-card"]')
    await expect(advisorCard).toContainText('Target web server is running nginx/1.27.0')

    const suggestedToolCard = page.locator('[data-testid="suggested-tool-card"]')
    await expect(suggestedToolCard).toBeVisible()
    await expect(suggestedToolCard).toContainText('tech_detect')
    await expect(suggestedToolCard).toContainText('Fingerprint web frameworks')

    // Tactical Chat interaction
    const chatInput = page.locator('[data-testid="advisor-chat-input"]')
    const chatSubmit = page.locator('[data-testid="advisor-chat-submit"]')
    await chatInput.fill('What are the immediate risks?')

    const [chatResponse] = await Promise.all([
      page.waitForResponse((res) => res.url().includes('/llm/chat')),
      chatSubmit.click()
    ])
    expect(chatResponse.status()).toBe(202)

    // Simulate LLM chat reply event
    await page.evaluate(() => {
      // @ts-ignore
      window.__dispatchSse('llm_chat_reply', {
        reply:
          'The absence of Content-Security-Policy permits unconstrained inline script execution. Recommend implementing a strict nonce-based CSP immediately.',
        timestamp: new Date().toISOString()
      })
    })

    const chatList = page.locator('[data-testid="advisor-chat-list"]')
    await expect(chatList).toContainText('The absence of Content-Security-Policy permits unconstrained inline script execution')

    // 6. Observation Promotion & Findings Curation
    const promoteObsBtn = page.locator('[data-testid="promote-observation-obs-http-01"]')
    await promoteObsBtn.click()

    const findingsDrawer = page.locator('[data-testid="findings-drawer"]')
    await expect(findingsDrawer).toBeVisible()

    // Save promoted finding
    const saveFindingBtn = page.locator('[data-testid="finding-submit-button"]')
    await saveFindingBtn.click()

    const finding1Card = page.locator('[data-testid="finding-card-finding-01"]')
    await expect(finding1Card).toBeVisible()
    await expect(finding1Card).toContainText('OPEN')

    // Confirm finding
    const confirmFindingBtn = page.locator('[data-testid="confirm-finding-finding-01"]')
    await confirmFindingBtn.click()
    await expect(finding1Card).toContainText('CONFIRMED')

    // Attach evidence snippet
    const attachEvidenceToggle = page.locator('[data-testid="add-evidence-toggle-finding-01"]')
    await attachEvidenceToggle.click()

    const evidenceInput = page.locator('[data-testid="evidence-snippet-input-finding-01"]')
    await evidenceInput.fill('Server: nginx/1.27.0\nMissing CSP')
    const evidenceSubmit = page.locator('[data-testid="evidence-submit-finding-01"]')
    await evidenceSubmit.click()

    const evidenceList = page.locator('[data-testid="finding-evidence-list-finding-01"]')
    await expect(evidenceList).toContainText('Server: nginx/1.27.0')

    // Create a second manual finding and reject it
    const manualFindingBtn = page.locator('[data-testid="new-finding-button"]')
    await manualFindingBtn.click()

    const titleInput = page.locator('[data-testid="finding-title-input"]')
    const descInput = page.locator('[data-testid="finding-description-input"]')
    await titleInput.fill('False Positive CVE-2024-9999')
    await descInput.fill('Suspected vulnerability debunked by source audit')
    await saveFindingBtn.click()

    const finding2Card = page.locator('[data-testid="finding-card-finding-02"]')
    await expect(finding2Card).toBeVisible()

    // Reject second finding with required reason
    const rejectToggle = page.locator('[data-testid="reject-finding-toggle-finding-02"]')
    await rejectToggle.click()

    const rejectReasonInput = page.locator('[data-testid="reject-reason-input-finding-02"]')
    await rejectReasonInput.fill('Verified not exploitable in staging environment')

    const rejectSubmitBtn = page.locator('[data-testid="reject-finding-submit-finding-02"]')
    await rejectSubmitBtn.click()

    await expect(finding2Card).toContainText('REJECTED')
    await expect(finding2Card).toContainText('Verified not exploitable in staging environment')

    // Close findings drawer to return to workspace actions
    const closeDrawerBtn = page.locator('[data-testid="close-findings-drawer-button"]')
    await closeDrawerBtn.click()
    await expect(findingsDrawer).not.toBeVisible()

    // 7. Complete the session
    const completeBtn = page.locator('[data-testid="complete-session-button"]')
    await completeBtn.click()
    await expect(page.locator('[data-testid="workspace-state-badge"]')).toHaveText('COMPLETED')

    // 8. Export Report -> Navigate to Screen 4 (/sessions/:id/report)
    const exportReportBtn = page.locator('[data-testid="open-report-view-button"]')
    await exportReportBtn.click()

    await expect(page).toHaveURL(/.*\/sessions\/sess-test-01\/report/)

    const reportIframe = page.locator('[data-testid="report-preview-iframe"]')
    await expect(reportIframe).toBeVisible()

    // Verify report HTML contains executive summary, active finding, evidence, and Section 5 Appendix
    const srcdoc = await reportIframe.getAttribute('srcdoc')
    expect(srcdoc).not.toBeNull()
    expect(srcdoc).toContain('Executive Summary')
    expect(srcdoc).toContain('[MISSING_HEADER] Missing Content-Security-Policy header')
    expect(srcdoc).toContain('Server: nginx/1.27.0')
    expect(srcdoc).toContain('Section 5: Rejected Findings Appendix')
    expect(srcdoc).toContain('False Positive CVE-2024-9999')
    expect(srcdoc).toContain('Verified not exploitable in staging environment')
  })
})
