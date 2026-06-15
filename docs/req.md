# Mini WAF — Distilled Technical Requirements

## Overview

A single-binary reverse proxy WAF written in **Rust**. Every request/response passes through it; the backend requires zero changes.

```
Internet → [WAF] → Backend
```

**Start command:** `./waf run`
**Target binary:** amd64 Linux, no runtime dependencies, no Docker required

---

## Performance SLA

| Metric | Requirement |
|--------|-------------|
| p99 latency overhead | ≤ 5 ms |
| Throughput baseline | ≥ 5,000 req/s |

---

## Tiered Protection Policy

| Tier | Route Patterns | Fail Mode |
|------|---------------|-----------|
| CRITICAL | `/login` `/otp` `/deposit` `/withdrawal` | **Fail-close** (deny all on WAF error) |
| HIGH | `/game/*` `/api/*` `/user/*` | Fail-open |
| MEDIUM | `/static/*` `/assets/*` `/public/*` | Fail-open |
| CATCH-ALL | `/**` | Fail-open |

All tiers: inbound + outbound inspection, audit log, risk score, global blacklist.

Fail-close / fail-open must be **configurable per tier** in the rule file — never hardcoded.

---

## Core Features

### 1. Rule Engine
- Match on: IP, Path, Header, Payload, Cookie
- Operators: regex, wildcard, exact match, logical AND/OR
- Each rule defines: `condition`, `action` (allow/block/challenge/rate-limit), `risk_score_delta`
- Rule scope: global, per-tier, per-route-pattern, per-IP, per-session, per-device
- Rule priority: numeric, resolves conflicts when multiple rules match
- **Hot-reload mandatory** — add/edit/delete rules without rebuilding or restarting

### 2. Rate Limiting
- Sliding window per **IP** AND per **user-session** (not just per IP)
- Token bucket for burst control
- Configurable threshold per route tier

### 3. DDoS Protection
- Burst detection + auto-block
- Configurable thresholds per tier
- Must handle DDoS targeting the WAF itself (graceful degradation scoring)

### 4. Challenge Engine
- JS Challenge
- Proof-of-Work
- Adaptive decision: Allow / Challenge / Block based on accumulated risk score

### 5. Relay & Proxy Detection
- Proxy chain detection
- X-Forwarded-For chain validation
- Abnormal header pattern detection
- ASN classification: residential vs datacenter vs Tor

### 6. IP Whitelist / Blacklist
- IP & FQDN whitelist
- Threat-intel blacklist loaded from file at startup (Tor exit list, bad ASN)
- Auto risk-score boost for known-bad IPs

### 7. Smart Caching
- CRITICAL tier: **no caching**
- MEDIUM tier (`/static`, `/assets`): aggressive caching
- Configurable TTL per route pattern

### 8. Device Fingerprinting
- Persistent device ID derived from: TLS fingerprint (JA3/JA4), HTTP/2 settings, User-Agent entropy, Accept-Encoding pattern
- Detect same device rotating IPs to bypass blocks

### 9. Behavioural Anomaly Detection
- Too-uniform request timing (bot indicator)
- Zero-depth session: hitting CRITICAL route without passing through homepage first
- Missing Referer on sensitive routes
- Inter-request interval < 50 ms

### 10. Transaction Velocity & Sequence
- Per-user cross-route tracking: Login → OTP → Deposit within N seconds
- Withdrawal velocity check after deposit
- Rapid limit-change pattern detection

---

## Attack Detection Coverage (OWASP minimum)

| Vector | Detection Scope |
|--------|----------------|
| SQLi | Classic, blind, time-based, UNION-based — URL params, headers, JSON body |
| XSS | Reflected & stored — query strings, form data, JSON |
| Path Traversal | `../` sequences, URL-encoded variants (`%2e%2e`) in path & query |
| SSRF | Requests to `10.x`, `172.16.x`, `192.168.x`, `169.254.x`, metadata endpoints |
| HTTP Header Injection | Host header injection, CRLF injection, X-Forwarded-For spoofing |
| Brute Force / Credential Stuffing | Per-user failed login counter, password spraying (many users, same IP) |
| Error Scanning / Recon | Rapid 4xx/5xx pattern, endpoint enumeration, OPTIONS abuse |
| Request Body Abuse | Malformed JSON, oversized payload (configurable limit), deeply nested objects, content-type mismatch |

---

## Risk & Challenge Engine

- Risk score accumulates per `{IP + device fingerprint + session}` — does **not** reset per request
- **Increases on:** rule match, failed challenge, behavioural anomaly, suspicious ASN, device fingerprint conflict
- **Decreases on:** successful challenge, sustained normal behaviour over a time window
- Configurable thresholds:
  - score < 30 → Allow
  - 30–70 → Challenge
  - > 70 → Block
- **Canary / Honeypot endpoints** (e.g. `/admin-test`, `/api-debug`): any hit → risk score set to MAX, IP blocked immediately

---

## Response Filtering (Outbound)

- Block responses containing: stack traces, internal IPs, API keys, verbose 5xx bodies exceeding configurable size
- Mask/redact configurable sensitive JSON fields (e.g. `card_number`, `bank_account`)
- Block accidental PII leakage in response headers (`X-Debug`, `X-Internal-*`)

---

## Graceful Degradation

- CRITICAL tier: fail-close on WAF internal error
- MEDIUM / CATCH-ALL: fail-open under overload, log warning
- **Circuit breaker** for upstream backend: return 503 if backend is unresponsive (no hanging connections)

---

## Realtime Dashboard

- Live request feed: request ID, timestamp (ms), risk score, action taken, rule triggered
- Attack visualisation: attack type distribution, top attacker IPs, route heatmap
- Hot config: update rules, toggle actions, adjust thresholds — **no service restart**
- Structured audit log: JSON, append-only, SIEM-ingestible
  - Fields: `request_id`, `ts_ms`, `ip`, `device_fp`, `risk_score`, `rule_id`, `action`

---

## Rule File Format

- YAML or TOML
- Mandatory fields per rule: `condition`, `action`, `risk_score_delta`
- Hot-reload: no binary rebuild, no service restart

---

## Bonus Features (extra points)

| Feature | Notes |
|---------|-------|
| HTTPS / TLS termination | mTLS support, configurable cipher suites |
| Geographic restriction | GeoIP (MaxMind lite), block/challenge by jurisdiction, VPN geo-bypass detection |
| IP Reputation Feed | Tor exit list + bad ASN, periodic refresh |
| Multi-region deployment | `waf deploy --region=sg,eu,us`, config sync |
| Zero-downtime config sync | Rolling update, config versioning |
| Auto scaling | Horizontal scaling with shared state via Redis/etcd |
| Behavioural ML scoring | Lightweight model classifying bot vs human from request sequence |

---

## Attack Scenarios (Red Team)

| # | Vector | Techniques |
|---|--------|-----------|
| 01 | DDoS L4/L7 | TCP/UDP flood, HTTP flood, Slowloris, RUDY; WAF self-DDoS |
| 02 | Credential Stuffing | Brute force, password spray, IP rotation |
| 03 | Relay / Proxy | Proxy chain, abnormal XFF, VPN/Tor, datacenter IP → `/login` |
| 04 | Device FP Evasion | Rotate TLS fingerprint, cycle UA, spoof residential IP |
| 05 | Behavioural Bypass | Zero-depth session, timed bot, spoofed Referer |
| 06 | Transaction Fraud | Login→Deposit < 5s, rapid withdrawal, limit-change + withdraw |
| 07 | OWASP Injection | Blind SQLi, XSS in JSON, SSRF, path traversal |
| 08 | Recon / Canary | Endpoint enumeration, honeypot probing, OPTIONS abuse, error harvesting |

---

## Scoring Summary

| Criterion | Points |
|-----------|--------|
| Security Effectiveness (detect rate, FP, OWASP, fingerprinting, behavioural, canary) | 40 |
| Performance (latency, throughput, memory, DDoS behaviour) | 20 |
| Intelligence & Adaptiveness (risk accuracy, transaction detection, degradation) | 20 |
| Architecture & Code Quality (idiomatic Rust, error handling, tests) | 15 |
| Extensibility (hot-reload, per-scope rules, plugin-ready, response filtering) | 10 |
| Dashboard UI/UX & Realtime Config | 10 |
| Deployment & Operability (single binary, one-command start, circuit breaker) | 5 |
| **Total** | **120** |

---

## Hard Rules

- WAF must protect **all routes** — no selective proxying
- CRITICAL tier must have **all policies fully implemented**
- Cross-route anomalies must be detected automatically (Login→Deposit, zero-depth session)
- Demo must use **real traffic** — no mocked responses
- **No manual intervention** during the Attack Battle
