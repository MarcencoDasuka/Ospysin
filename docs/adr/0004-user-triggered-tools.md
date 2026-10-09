# ADR 0004: Explicit User-Triggered Tool Invocations

## Status
Accepted

## Context
When performing security audits, every packet sent to a target host is a potential legal and operational event. If software triggers scans in the background automatically (e.g. automatically querying WHOIS or resolving all discovered URLs as soon as a domain is typed), the operator may inadvertently violate engagement scopes or alert defensive security monitoring systems (WAF, SIEM).

## Decision
Every tool execution requires an **explicit, discrete user action** (a physical button click in the UI or an explicit REST POST call).

Rules:
1. No tool is automatically triggered upon creating a session or loading a URL.
2. Background pre-fetching of links, scripts, or DNS entries is prohibited.
3. Recommendations presented by the AI advisor are rendered as clickable quick-action buttons; the operator must actively click the button to proceed.

## Consequences
### Positive:
- Precise operator intent: No accidental network traffic generated without the user knowing.
- Clean forensic timestamps corresponding to deliberate human actions.
- Full compliance with strict third-party Rules of Engagement and bug bounty policies.

### Negative:
- Requires slightly more clicks compared to fully automated scanners like Acunetix or Nessus.

## Alternatives Considered
- **Automated Workflow Cascades (run all passive tools automatically on session creation)**: Rejected to preserve operator control and avoid uncoordinated traffic spikes.
