# ADR 0003: LLM as Advisory Sounding Board

## Status
Accepted

## Context
Many modern security tools experiment with autonomous "AI Agent" architectures, allowing LLMs to autonomously run terminal commands, execute port scans, and exploit vulnerabilities in feedback loops.

In cybersecurity auditing, autonomous AI execution introduces catastrophic risks:
- Hallucinated exploit payloads targeting unintended hosts.
- Unpredictable network floods violating Rules of Engagement.
- Loss of forensic accountability and chain of custody.
- High vulnerability to prompt injection attacks embedded in untrusted web pages.

## Decision
We enforce an architectural boundary: **The LLM is an active vulnerability and exploitability advisor for self-defense, but MUST NEVER possess autonomous execution rights or direct network access.**

Implementation rules:
1. The LLM receives structured, sanitized tool results from the backend.
2. The LLM actively inspects the data for active security breaches, exploit vectors, and misconfigurations, explaining how an attacker could compromise the asset and how to fix it.
3. The LLM suggests specific registered verification tools (`suggested_tool`) to deepen the audit.
4. The backend validates any suggested tool against the registered catalog.
5. The frontend renders the suggestion as a UI quick-action button; **only the human operator can trigger execution**.

## Consequences
### Positive:
- Complete safety guarantee: Prompt injection inside target HTML cannot hijack execution or trigger unauthorized network actions.
- Legal clarity: The operator maintains 100% intentionality and responsibility for every request sent across the wire.
- High interpretability: The auditor learns from the model's explanations rather than watching a black-box autonomous script run wild.

### Negative:
- Does not offer fully automated "one-click hands-off penetration testing" (which is an intentional non-goal).

## Alternatives Considered
- **Autonomous Agentic Loop (ReAct / AutoGPT pattern)**: Rejected due to safety, legal liability, and nondeterminism.
