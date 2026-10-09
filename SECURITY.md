# Security Policy

## Supported Versions

Only the latest minor release of Ospysin receives active security patches.

| Version | Supported          |
| :---    | :---               |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability in Ospysin

If you identify a security vulnerability within the Ospysin platform itself (e.g., SSRF bypass in `PolicyEngine`, remote code execution vector, SQL injection, or UI XSS):

1. **Do NOT open a public GitHub issue.**
2. Send an email to the security response address:
   `security@ospysin.local` (or file a private GitHub Security Advisory).
3. Include the following details:
   - Affected version or commit hash.
   - Step-by-step reproduction guide or minimal proof-of-concept.
   - Potential impact (e.g., policy bypass from `PUBLIC` mode to internal network).
   - Any suggested patch or remediation.

---

## Vulnerability Response Timelines

- **Initial Acknowledgment**: Within 48 hours.
- **Triage & Reproduction**: Within 5 business days.
- **Remediation & Patch Release**: Within 14 business days for critical issues.

---

## Responsible Disclosure & Safe Harbor

We fully support responsible disclosure. We pledge not to pursue legal action against researchers who:
- Test vulnerabilities against their own local installations.
- Avoid accessing, modifying, or destroying third-party or shared data.
- Allow adequate time for patches before public disclosure.
