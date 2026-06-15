# mini-waf

A lightweight Web Application Firewall built in Rust for WAF Mini Hackathon 2026.

Single binary — `./waf run --config config/waf.toml` — that runs a reverse proxy and a dashboard REST API concurrently.

---

## Quick start

```bash
# Build
make build

# Run (proxy :8080, dashboard API :9090)
make run

# Or run the binary directly
./target/debug/waf run --config config/waf.toml
```

---

## Architecture

```
Client → waf-proxy (:8080)
              │
              ├─ waf-engine   (detection pipeline)
              ├─ Backend       (upstream :3000)
              └─ waf-api (:9090) ← Dashboard
```

See [docs/architecture.md](docs/architecture.md) for the full node diagram.

---

## WAF use cases

<!-- USE_CASES_START — managed by agents; do not edit this block manually -->

### Implemented (binary responds correctly)

| # | Use case | Trigger | Response |
|---|----------|---------|----------|
| 1 | **Reverse proxy passthrough** | Any clean request | Forwarded to upstream; upstream response returned to client |
| 2 | **Dashboard metrics API** | `GET /api/metrics` | JSON snapshot of request counters |
| 3 | **Dashboard rules API** | `GET /api/rules` | JSON rule list |
| 4 | **Dashboard config API** | `POST /api/config` | Runtime threshold update |
| 5 | **WebSocket live feed** | `GET /ws/feed` | WS upgrade; streams audit events |
| 6 | **Config hot-load** | `config/waf.toml` read at startup | All thresholds, tier routes, circuit-breaker wired |
| 7 | **Structured audit log** | Every accepted connection | NDJSON appended to `logs/audit.jsonl` |
| 8 | **Decision enforcement (HTTP)** | Pipeline decision | Block → 403, RateLimit → 429 (Retry-After header), Challenge → 403, Allow → proxied |

### Designed / stubbed (rules loaded but pipeline not yet wired)

| # | Use case | Detection module | Config rule |
|---|----------|-----------------|-------------|
| 9  | **SQLi detection** | `waf-engine/detection/sqli.rs` | `global-sqli-detect` |
| 10 | **XSS detection** | `waf-engine/detection/xss.rs` | `global-xss-detect` |
| 11 | **Path traversal** | `waf-engine/detection/path_traversal.rs` | `global-path-traversal` |
| 12 | **SSRF detection** | `waf-engine/detection/ssrf.rs` | `global-ssrf-detect` |
| 13 | **HTTP header injection / CRLF** | `waf-engine/detection/header_injection.rs` | `global-header-injection` |
| 14 | **Canary / honeypot endpoints** | `waf-engine/risk/canary.rs` | `global-canary-admin-test`, `global-canary-api-debug` |
| 15 | **IP blacklist / whitelist** | `waf-engine/lists/ip_list.rs` | `global-block-blacklisted-ip`, `global-allow-whitelisted-ip` |
| 16 | **Per-IP rate limiting (sliding window)** | `waf-engine/rate_limit/sliding_window.rs` | `critical-rate-limit-ip`, `high-rate-limit-ip`, `medium-rate-limit` |
| 17 | **Per-IP rate limiting (token bucket)** | `waf-engine/rate_limit/token_bucket.rs` | — |
| 18 | **DDoS / burst detection** | `waf-engine/ddos/burst.rs` | — |
| 19 | **Brute-force detection** | `waf-engine/detection/brute_force.rs` | `critical-brute-force-detect` |
| 20 | **Body abuse detection** | `waf-engine/detection/body_abuse.rs` | — |
| 21 | **Recon / scanning detection** | `waf-engine/detection/recon.rs` | — |
| 22 | **Behaviour anomaly detection** | `waf-engine/behaviour/anomaly.rs` | — |
| 23 | **Device fingerprinting (JA3/JA4 + UA)** | `waf-engine/fingerprint/` | — |
| 24 | **Proxy / relay detection** | `waf-engine/proxy_detect/` | — |
| 25 | **Risk scoring + threshold enforcement** | `waf-engine/risk/scorer.rs` | `[risk] allow_threshold`, `challenge_threshold` in waf.toml |
| 26 | **JS / PoW challenge issuance** | `waf-engine/challenge/` | `critical-zero-depth-session` |
| 27 | **Response cache (MEDIUM tier)** | `waf-engine/cache/store.rs` | `[cache] ttl_medium_secs` in waf.toml |
| 28 | **Upstream circuit breaker** | `waf-proxy/upstream.rs` | `[circuit_breaker]` in waf.toml |
| 29 | **Outbound response filtering** | `waf-engine/pipeline.rs` (run_outbound) | Stack-trace/PII leak prevention |
| 30 | **TLS termination + JA3/JA4 capture** | `waf-proxy/tls.rs` | — |
| 31 | **Transaction velocity checks** | — | `critical-transaction-velocity` |
| 32 | **Hot-swap rules via API** | `waf-api/routes/rules.rs` | `POST /api/rules` |
| 33 | **OWASP CRS integration** | `rules/crs/` — `CrsPlugin` registers `crs_score()` / `crs_match()` GRL built-ins; CRS anomaly scoring wired through detection.grl | Block when CRS inbound anomaly score ≥ 5 via `CrsBlock` GRL rule |

<!-- USE_CASES_END -->

---

## Running the REST test client

Requires the WAF to be running (`make run`) and the backend to be on `:3000`.

```bash
.venv/bin/python tests/rest_client.py
# verbose response bodies:
.venv/bin/python tests/rest_client.py --verbose
```

---

## Project layout

```
crates/
  waf-types/      shared enums (Decision, Tier, RiskScore, AuditEntry)
  waf-engine/     detection pipeline, rules, rate-limit, risk, cache, audit
  waf-proxy/      TCP accept loop, request handler, upstream forwarding
  waf-api/        axum REST + WebSocket dashboard API
  waf/            binary entry point (CLI)
config/
  waf.toml        master runtime config
  rules/*.yaml    YAML rule files
dashboard/        Node.js/TypeScript dashboard (npm start)
tests/
  rest_client.py  Python integration test client
  fixtures/       sqli_payloads.txt, xss_payloads.txt
docs/
  req.md          distilled technical requirements
  architecture.md architecture diagram
```
