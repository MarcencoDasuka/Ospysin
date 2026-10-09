# 07. Policy Engine Specification

## Overview
The Policy Engine is the foundational network safety and authorization gatekeeper in Ospysin. Every network operation requested by a tool MUST pass through the Policy Engine before any socket is opened.

> **CLARIFICATION**: The Policy Engine is **NOT** content filtering or LLM censorship. It is deterministic network security engineering designed to prevent SSRF (Server-Side Request Forgery), DNS rebinding, internal subnet scanning, and denial-of-service against third-party systems.

---

## Operational Modes: LOCAL vs PUBLIC

Policy enforcement is governed by the authoritative **IANA Special-Purpose Address Registries (RFC 6890)**, cloud provider metadata endpoints, and session boundaries.

| Policy Dimension | `LOCAL` Mode | `PUBLIC` Mode | Registry / RFC Source |
| :--- | :--- | :--- | :--- |
| **Intended Target** | Developer localhost, LAN appliances, internal staging. | Public internet hosts and web applications. | N/A |
| **Loopback (`127.0.0.0/8`, `::1/128`)** | **ALLOWED** | **BLOCKED** | RFC 1122 / RFC 4291 |
| **Private RFC 1918 (`10/8`, `172.16/12`, `192.168/16`)** | **ALLOWED** | **BLOCKED** | RFC 1918 / RFC 6890 |
| **Unique Local IPv6 (`fc00::/7`)** | **ALLOWED** | **BLOCKED** | RFC 4193 / RFC 6890 |
| **Shared Address Space / CGNAT (`100.64.0.0/10`)** | **BLOCKED** | **BLOCKED** | RFC 6598 / RFC 6890 |
| **Link-Local (`169.254.0.0/16`, `fe80::/10`)** | **BLOCKED** | **BLOCKED** | RFC 3927 / RFC 4291 |
| **Cloud Metadata (`169.254.169.254`, `[fd00:ec2::254]`, `100.100.100.200`)** | **BLOCKED** | **BLOCKED** | AWS / GCP / Azure / Alibaba Metadata |
| **Documentation & Benchmarking (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `198.18.0.0/15`)** | **BLOCKED** | **BLOCKED** | RFC 5737 / RFC 3849 / RFC 2544 |
| **Multicast & Reserved (`224.0.0.0/4`, `ff00::/8`, `240.0.0.0/4`, `255.255.255.255/32`)** | **BLOCKED** | **BLOCKED** | RFC 5771 / RFC 1112 / RFC 919 |
| **IPv4-Mapped IPv6 (`::ffff:0:0/96`)** | **UNWRAPPED & EVALUATED** | **UNWRAPPED & EVALUATED** | RFC 4291 (Unwrapped to underlying IPv4) |
| **Public Routable IPv4 / IPv6** | **ALLOWED** | **ALLOWED** | Globally Routable |

---

## Core Safety Rules

### 1. Scheme Allowlist & Category Policies
- **HTTP / TLS Tools**: Allowed schemes: `http` and `https` only. Restricted ports: default ports (80, 443) or designated alternative web ports (8000, 8080, 8443, 3000, 5000). Rejected schemes: `file://`, `gopher://`, `ftp://`, `ldap://`, `dict://`, `data://`.
- **WHOIS & RDAP Tools**: Connects outbound to port 43 TCP or port 443 HTTPS. Authoritative root discovery uses IANA bootstrap registries. Prefer **RDAP** (RFC 7480-7484 over HTTPS) where supported. Referral hosts (`ReferralServer: whois://...`) are NEVER contacted blindly: referral hostnames must be resolved via DNS and checked by PolicyEngine (blocking private/metadata destinations).
- **Offline Analytical Tools**: Purely local computation. Network sockets are strictly forbidden. Evaluates object-level authorization verifying that referenced `stepId` belongs to the requesting session.

### 2. DNS Pre-Flight Resolution, IP Pinning & RFC 9525 TLS Verification
To defend against time-of-check to time-of-use (TOCTOU) DNS rebinding:
1. `PolicyEngine` resolves all A and AAAA records for the target hostname using `InetAddress.getAllByName(hostname)`.
2. In `PUBLIC` mode, **every resolved IP address** is validated against the special-purpose denylist. If any address is prohibited, the domain is rejected (`DENY`).
3. For IPv4-mapped IPv6 addresses (`::ffff:0:0/96`), the parser extracts the embedded IPv4 address and re-evaluates it against the IPv4 denylist.
4. If approved, the HTTP connection manager is pinned to the single pre-validated `InetAddress` using an in-memory `DnsResolver`.
5. The connection initiates to the target URL (`https://example.com/`):
   - **TLS SNI (Server Name Indication)**: The TLS `ClientHello` handshake transmits `example.com` in the SNI extension (RFC 6066).
   - **TLS Service Identity Verification**: The peer certificate is verified strictly per **RFC 9525**, matching `example.com` against Subject Alternative Name (SAN) `dNSName` entries (deprecated commonName fallback is omitted).
   - **HTTP Host Header**: Emits `Host: example.com`.

### 3. Scope Containment & Redirect Revalidation
- **Scope Invariant**: Every tool execution must match an authorized `ScopeAsset`. In v1, scope is strictly locked to the original target host confirmed at session creation and **never expands automatically**. Discovered third-party links or CDNs are stored solely as observational data.
- **HTTP Redirect Revalidation (`301`, `302`, `307`, `308`)**:
  - Automatic redirect following is disabled by default.
  - If enabled (`followRedirects: true`), each redirect hop (capped at **3 hops**) triggers full re-validation: parses the `Location` header, enforces scheme allowlist, resolves DNS, evaluates all resolved IPs through `PolicyEngine`, and re-pins the socket IP before opening the next connection.

### 4. Rate Limiting & Concurrency Controls
- **Granularity**: Pacing is strictly applied per **`(session_id, target_hostname)`** pair, never globally.
- **Queueing & Per-Target Concurrency**: Multiple distinct tools MAY be queued as `PENDING`. At most **one** execution may be `RUNNING` per session/target host at any given time.
- **Pacing & Throughput**: Maximum 2 requests per second to the destination host. A mandatory 500ms cool-down is enforced between consecutive completed executions against the same target.

### 5. Reconciled 4-Tier Payload & Resource Bounds

| Constraint Tier | Limit | Description & Enforcement |
| :--- | :--- | :--- |
| **Tier 1: Encoded Wire Bytes** | 1 MB max (64 KB for headers) | Maximum raw encoded bytes read from the socket per single response before decompression. Enforced via socket stream counter. |
| **Tier 2: Decompressed Bytes** | 2 MB max per response | Absolute cap on uncompressed plaintext bytes per response. Enforced via `BoundedInputStream`. |
| **Tier 2 Expansion Ratio** | 10:1 ratio cap | Evaluated once decompressed bytes $D > 100 \text{ KB}$. If $D / \max(C, 1) > 10$, stream terminates immediately with `DecompressionBombException`. |
| **Tier 3: Aggregate Tool Limit** | 5 MB aggregate | Maximum total decompressed bytes processed across all downloaded assets in a single tool run (e.g. `js_secrets_scanner`, max 10 files $\times$ 512 KB). |
| **Tier 4: Persisted Result Limit**| 1 MB per `tool_results` row | Maximum size for `raw_output` text and `parsed_data` JSONB in PostgreSQL. Multi-asset tools summarize and truncate payloads to fit within 1 MB. |
| **Timeouts** | Connect: 5s, Read: 10–20s | Timeouts configured per tool in Tool Catalog. Target timeouts are terminal failures without automatic retries. |

---

## Policy Decision Contract & Audit Logging

Every evaluation produces a structured `PolicyDecision` object:

```java
public record PolicyDecision(
    boolean allowed,
    String reason,
    String targetHost,
    InetAddress resolvedIp,
    AuditMode mode,
    long evaluationTimestamp
) {}
```

### Forensic Audit Log Recording
Every `PolicyDecision` is written to `audit_events`:
- Timestamp, target URL, and evaluated IP address.
- Applied rule check results (scheme, IP range, redirect check).
- Decision outcome (`ALLOW` or `DENY`).
- If denied, the exact rule identifier and rationale are presented to the operator in the UI.
