# 09. Legal and Ethical Guidelines

## Overview
Ospysin is an engineering instrument for authorized reconnaissance, defensive vulnerability posture assessment, and compliance auditing. Operating this platform against systems without explicit, verifiable permission carries criminal and civil liability.

---

## Legal Framework & Statutory Compliance

Security testing without authorization is prohibited by criminal law in most jurisdictions:

- **Republic of Moldova**: Criminal Code Art. 259 (*"Neautorizată a accesului la informația computerizată"* / Unauthorized access to computerized information) and Art. 260 (*"Producerea, importul, comercializarea sau punerea la dispoziție a mijloacelor tehnice ori a programelor pentru calculator"*).
- **European Union**: Directive 2013/40/EU on attacks against information systems (criminalizing unauthorized access, illegal system interference, and illegal data interference).
- **International Standards**: Budapest Convention on Cybercrime (ETS No. 185) Art. 2–6.
- **United States**: Computer Fraud and Abuse Act (18 U.S.C. § 1030).

---

## Authorization Assertions & Operational Modes

To ensure strict legal boundaries, Ospysin enforces explicit authorization assertions at session creation:

### 1. `LOCAL` Mode: Asset Ownership Assertion
- **Scope**: Local workstation loopback (`127.0.0.1`, `localhost`) and private RFC 1918 LAN environments.
- **Operator Assertion**: By selecting `LOCAL` mode, the operator formally asserts sole ownership or full administrative authorization over the local system and private network.

### 2. `PUBLIC` Mode: Written Authorization Assertion
- **Scope**: Internet-routable domains, public IP addresses, and external web properties.
- **Operator Assertion**: By selecting `PUBLIC` mode, the operator warrants that they possess an active, written authorization agreement (such as a Penetration Testing Agreement, Rules of Engagement document, or valid Bug Bounty program policy covering the specified asset).

---

## Mandatory Scope Acknowledgment Gate (Attestation Ledger)

Before any tool in the catalog can be triggered, the operator must complete the interactive scope gate attesting to authorized inspection:

```text
[X] Statement Version 1.0.0:
    "I certify under penalty of law that I own this asset or have received explicit,
     written authorization to conduct security inspection against the target URL.
     I understand that all actions are forensically recorded in the local immutable audit log."
```

### Server Record Storage & Verification
The backend enforces:
1. **Timestamped Event**: An explicit `SCOPE_ACKNOWLEDGED` event written to `audit_events`.
2. **Server-Authoritative Text & Digest**: The client submits only the agreed `scopeAckVersion` (e.g. `1.0.0`). The backend retrieves the authoritative server-stored statement text, computes its SHA-256 digest, and records `scope_ack_hash` and `scope_ack_timestamp`.
3. **Audit Report Linkage**: The generated HTML/PDF audit report embeds the acknowledgment timestamp, statement version, and SHA-256 digest on the title page.

### Epistemic & Legal Boundaries of Attestation Records
The recorded attestation establishes strict internal chain-of-custody, but carries explicit legal boundaries:
- **What it Demonstrates**: It proves *what the server recorded*—that a local user session submitted an electronic attestation selecting statement version 1.0.0 at an authoritative timestamp, providing non-repudiation of the operator's submission within the local platform.
- **What it Does NOT Prove**: The hash and event log **DO NOT prove** actual legal ownership of the target domain/IP, **DO NOT prove** that written authorization was genuinely granted by the asset owner, **DO NOT prove** that the human operator read or understood the terms, and **DO NOT confer statutory immunity** under computer fraud statutes (e.g. CFAA 18 U.S.C. § 1030 or EU Directive 2013/40/EU). Full legal liability for all transmitted network packets remains solely with the operating individual.

---

## Immutable Audit Trail as Forensic Evidence

All tool executions, request parameters, responses, policy checks, and operator actions are recorded in an append-only database table (`audit_events`).
- **Chain of Custody**: Cryptographic hashes of raw results are maintained alongside timestamps.
- **Exportable Evidence**: The log can be exported as a signed audit record to demonstrate strict adherence to agreed Rules of Engagement in the event of dispute or compliance audits.

---

## Vulnerability Handling & Responsible Disclosure

If non-destructive inspection accidentally uncovers critical vulnerabilities (e.g. exposed environment credentials in public scripts, unsecured directory listings with sensitive customer data):
1. **Cease Further Probing**: Do not attempt to exploit or extract additional records.
2. **Document Findings**: Use Ospysin's observation and finding features to record the factual state.
3. **Notify System Owner**: Coordinate disclosure using the target's declared security contact (`/.well-known/security.txt`), CERT-RO / relevant national CSIRT, or formal reporting channels.
4. **Maintain Confidentiality**: Withhold public disclosure until remediation has been verified.
