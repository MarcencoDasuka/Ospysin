# 10. UI/UX Specification

## Overview
Ospysin provides a responsive, object-based single-page application built with **Vue 3**, **PrimeVue**, and **Tailwind CSS**. Rather than mimicking terminal or hacker aesthetics, the interface prioritizes structured data clarity, predictable object manipulation, and clean visual status states.

---

## Screen Definitions

### Screen 0: Login View
- **Components**: Username input, Password input, Sign-In button, error callout.
- **Behavior**: Submits credentials to `POST /api/auth/login`. Sets `HttpOnly; SameSite=Strict` cookie `JSESSIONID` and redirects to Session List.

```text
+-------------------------------------------------------------------+
| Ospysin — Operator Authentication                                 |
|                                                                   |
| Username: [ admin                                               ] |
| Password: [ ******************                                  ] |
|                                                                   |
|                                                  [ Sign In ]      |
+-------------------------------------------------------------------+
```

---

### Screen 1: Home / Session List
- **Header**: Project title, local health indicator, "New Audit Session" button, operator profile and logout.
- **Main View**: Data table displaying recent audit sessions with target URL, mode tag (`LOCAL` vs `PUBLIC`), execution step counts, finding counts, created timestamp, and quick-action links.

```text
+-----------------------------------------------------------------------------------------+
| [Ospysin Platform]                     Operator: admin [Logout]  Status: [Ollama: READY]|
+-----------------------------------------------------------------------------------------+
| Audit Sessions                                                    [+ New Audit Session] |
|                                                                                         |
| TARGET URL                 MODE      STEPS   FINDINGS   CREATED AT       ACTIONS        |
| https://example.com        PUBLIC    4       2          2026-10-09 01:20 [Open] [Report]|
| http://192.168.1.50:8080   LOCAL     7       0          2026-10-08 19:15 [Open] [Report]|
+-----------------------------------------------------------------------------------------+
```

---

### Screen 2: New Session Setup Modal
- Target URL input field with validation.
- Mode Selector: Segmented button (`LOCAL` vs `PUBLIC`) with informational tooltip explaining IP filtering rules.
- Mandatory Scope Acknowledgment Checkbox.
- Actions: "Cancel" and "Initialize Session".

```text
+-------------------------------------------------------------------+
| Start New Audit Session                                           |
|                                                                   |
| Target URL:                                                       |
| [ https://target.app.internal                                   ] |
|                                                                   |
| Inspection Mode:                                                  |
| ( ) LOCAL (Private IPs & Loopback)   (*) PUBLIC (Internet Only)   |
|                                                                   |
| [X] I certify that I have explicit authorization to inspect this  |
|     target asset and accept responsibility for network safety.    |
|                                                                   |
|                                        [Cancel]  [Start Session]  |
+-------------------------------------------------------------------+
```

---

### Screen 3: Session Workspace (4-Panel Layout)

The core operational interface features 4 persistent panels:
1. **Left Panel: Tool Catalog**: Categorized list of 15 tools across 3 canonical tiers:
   - **External Third-Party Recon**: `dns_lookup`, `whois_lookup` (Passive, external infrastructure queries).
   - **Active Direct Target Probes**: `tls_info`, `http_headers`, `robots_txt`, `sitemap_xml`, `extract_links`, `extract_js_urls`, `tech_detect`, `sensitive_files_check`, `js_secrets_scanner`, `cors_misconfig_check`, `subdomain_takeover_check` (Direct target connections).
   - **Offline Analytical**: `security_headers_score`, `cve_matcher` (Local computation over collected evidence).
   Execution triggers send `POST /api/sessions/{id}/tools/{toolId}/run`, queueing the job as `202 Accepted`.
2. **Center Panel: Inspection & Results**:
   - Header with active URL, Inspection Mode badge (`LOCAL` / `PUBLIC`), Session State (`ACTIVE`, `COMPLETED`, `ABORTED`), and action controls (`[Complete Session]`, `[Abort Session]`, `[Export Report]`).
   - Execution step timeline tabs with statuses (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`).
   - Dual-view result viewer (Tabs: `Parsed Structure` tree and `Raw Response` text).
   - **Curated Findings Drawer / Modal**: Allows operator to create findings (`POST /api/sessions/{id}/findings`), edit existing findings, or reject false positives (`POST /api/findings/{id}/reject`) via a mandatory rejection reason dialog.
3. **Right Panel: LLM Advisor**:
   - Automated commentary on the latest completed step (or manual trigger).
   - "Suggested Next Tool" quick-action card with reason.
   - Tactical chat input at the bottom for ad-hoc questions.
4. **Bottom Panel: Live Event Log**:
   - Collapsible real-time SSE stream log displaying timestamped events, policy checks, warnings, and queue lifecycle events.

```text
+------------------------------------------------------------------------------------------------------------------+
| Target: https://target.app.internal  Mode: [PUBLIC]  State: [ACTIVE]    [Complete Session] [Abort] [Export Report]|
+-----------------------+--------------------------------------------------+---------------------------------------+
| TOOL CATALOG (15)     | RESULTS & EXECUTION HISTORY                      | AI ADVISOR (Ollama: Cyber)            |
+-----------------------+--------------------------------------------------+---------------------------------------+
| THIRD-PARTY RECON     | Steps: [1. dns_lookup (OK)] [2. tls_info (OK)]   | Latest Commentary:                    |
| [ Run DNS Lookup    ] |                                                  | The server enforces HSTS              |
| [ Run WHOIS         ] | [ Parsed View ]  [ Raw Output ]  [ Add Finding ] | but lacks Content-Security-           |
|                       | +----------------------------------------------+ | Policy (CSP).                        |
| DIRECT TARGET PROBES  | | Status: 200 OK                               | |                                       |
| [ Run TLS Info      ] | | Headers:                                     | | Suggested Next Step:                |
| [ Run HTTP Headers  ] | |   Strict-Transport-Security: max-age=315...  | | [ Run robots.txt ]                  |
| [ Run robots.txt    ] | |   X-Frame-Options: DENY                      | | Reason: Inspect crawling policies   |
| [ ... (9 more)    ]   | | Cookies:                                     | | and unlisted endpoints.             |
|                       | |   SESSION: Secure, HttpOnly, SameSite=Lax    | |-------------------------------------|
| OFFLINE ANALYTICAL    | | Server: nginx/1.24.0                         | | Tactical Chat:                      |
| [ Run Headers Score ] | +----------------------------------------------+ | [Ask advisor...                 ] [>] |
| [ Run CVE Matcher   ] |                                                  |                                       |
+-----------------------+--------------------------------------------------+---------------------------------------+
| LIVE EVENT STREAM (SSE)                                                                        [^ Collapse]      |
| 01:42:01 [INFO] PolicyEngine: Approved request to 93.184.216.34 (PUBLIC mode)                                    |
| 01:42:02 [INFO] http_headers completed in 320ms                                                                 |
+------------------------------------------------------------------------------------------------------------------+
```

---

### Screen 4: Report View
- Clean, printable document layout.
- Executive summary, target information, operator attestation details, timestamp of audit.
- Full inventory of executed tools with status, timestamps, and durations.
- Human-curated Findings with severity tags (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
  - Active and confirmed findings are included in the primary report.
  - `REJECTED` findings are strictly excluded from the executive vulnerability list and relocated to an optional "Rejected Findings / False Positive Log" appendix showing operator justification and rejection timestamp.
- Evidence cards linking directly to raw output snippets.
- "Print / Export PDF" button with print-optimized CSS (`@media print`).

---

## Workspace Panel States

| State | Tool Catalog | Results Viewer | LLM Advisor | Event Log |
| :--- | :--- | :--- | :--- | :--- |
| **Empty** | All buttons active. | Empty placeholder: *"Select a tool to run"*. | Waiting for first execution. | Initialized, listening for events. |
| **Pending** | Target tool button shows queued indicator; other buttons remain active for queueing. | Queued card with position indicator. | Idle or shows previous commentary. | Appends `step_queued` event. |
| **Running** | Triggered button shows spinning loader; other buttons allow queueing distinct tools. | Skeleton loading cards. | Shows *"Executing inspection..."* loader. | Appends `step_started` event. |
| **Completed** | Returns to active state. | Renders interactive JSON tree and highlighted raw text. | Renders comment and suggestion pill. | Appends `step_finished` with duration. |
| **Error** | Returns to active state. | Displays RFC 9457 problem card with failure reason, type URI, and error detail. | Inactive or offers troubleshooting tip. | Appends `step_failed` or `policy_alert` in red. |
| **Aborted / Completed** | All execution buttons disabled. | Displays read-only results and summary. | Disables chat and suggestion actions. | Appends `session_completed` or `session_aborted`. |

---

## Server-Sent Events (SSE) Contract
The Vue frontend hooks into `GET /api/sessions/{id}/events` via `EventSource`:
- `step_queued`: Notifies UI of newly queued job (`202 Accepted`).
- `step_started`: Triggers running state in workspace center panel.
- `step_finished`: Replaces loading state with fresh step output.
- `step_failed`: Renders RFC 9457 problem detail card in results viewer.
- `llm_comment_ready`: Updates advisor panel with comment and suggestion button.
- `llm_chat_reply`: Appends assistant response to tactical chat thread.
- `policy_alert`: Triggers a non-blocking toast banner with policy details.
- `session_completed`: Marks session COMPLETED, locks execution controls, and enables final report generation.
- `session_aborted`: Marks session ABORTED, cancels pending spinners, and logs abortion reason.
