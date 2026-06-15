#!/usr/bin/env python3
"""
tests/rest_client.py — Manual integration test client for the mini-waf proxy.

Tests the basic request lifecycle through the proxy:
  1. Pass-through   — clean request should reach the backend (2xx)
  2. SQLi block     — payload in query string must be blocked (403)
  3. XSS block      — script tag in query string must be blocked (403)
  4. Path traversal — ../etc/passwd must be blocked (403)
  5. SSRF block     — body targeting internal IP must be blocked (403)
  6. Canary         — honeypot endpoint must be blocked (403)
  7. Rate limit     — burst past threshold must be rejected (429)
  8. Audit API      — /api/metrics on the dashboard API must respond (200)

Usage:
  python tests/rest_client.py                        # default: proxy=8111 api=8112
  python tests/rest_client.py --proxy 8111 --api 8112 --verbose
"""

import argparse
import json
import sys
import time

import httpx

# ── ANSI colours ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

PASS = f"{GREEN}PASS{RESET}"
FAIL = f"{RED}FAIL{RESET}"
SKIP = f"{YELLOW}SKIP{RESET}"


# ── Test runner ───────────────────────────────────────────────────────────────

class TestClient:
    def __init__(self, proxy_base: str, api_base: str, verbose: bool = False):
        self.proxy = httpx.Client(base_url=proxy_base, timeout=5.0)
        self.api   = httpx.Client(base_url=api_base,   timeout=5.0)
        self.verbose = verbose
        self.results: list[tuple[str, bool, str]] = []

    def close(self):
        self.proxy.close()
        self.api.close()

    # ── assertion helper ─────────────────────────────────────────────────────
    def check(self, name: str, response: httpx.Response, expected_status: int):
        ok = response.status_code == expected_status
        note = f"got {response.status_code}, expected {expected_status}"
        if self.verbose:
            try:
                body = response.json()
                note += f"\n    body: {json.dumps(body, indent=2)}"
            except Exception:
                note += f"\n    body: {response.text[:200]}"
        self.results.append((name, ok, note))
        label = PASS if ok else FAIL
        print(f"  [{label}] {name}  ({note})")
        return ok

    # ── individual test cases ─────────────────────────────────────────────────

    def test_passthrough(self):
        """A clean GET / should be forwarded and return whatever the backend returns.
        We accept any 2xx or 3xx — the important thing is it's NOT a 403/429/5xx
        originating from the WAF itself."""
        try:
            r = self.proxy.get("/")
            ok = r.status_code < 400 or r.status_code == 404  # 404 backend = pass-through
            note = f"got {r.status_code}"
            self.results.append(("Pass-through GET /", ok, note))
            label = PASS if ok else FAIL
            print(f"  [{label}] Pass-through GET /  ({note})")
        except httpx.ConnectError:
            self.results.append(("Pass-through GET /", False, "connection refused"))
            print(f"  [{SKIP}] Pass-through GET /  (WAF not running — skipped)")

    def test_sqli_blocked(self):
        try:
            r = self.proxy.get("/search", params={"q": "1' OR '1'='1"})
            self.check("SQLi in query string → 403", r, 403)
        except httpx.ConnectError:
            self._skip("SQLi in query string → 403")

    def test_sqli_body_blocked(self):
        try:
            payload = {"username": "admin' UNION SELECT NULL--", "password": "x"}
            r = self.proxy.post("/login", json=payload)
            self.check("SQLi in JSON body → 403", r, 403)
        except httpx.ConnectError:
            self._skip("SQLi in JSON body → 403")

    def test_xss_blocked(self):
        try:
            r = self.proxy.get("/search", params={"q": "<script>alert(1)</script>"})
            self.check("XSS in query string → 403", r, 403)
        except httpx.ConnectError:
            self._skip("XSS in query string → 403")

    def test_path_traversal_blocked(self):
        try:
            r = self.proxy.get("/../../../etc/passwd")
            self.check("Path traversal → 403", r, 403)
        except httpx.ConnectError:
            self._skip("Path traversal → 403")

    def test_path_traversal_encoded_blocked(self):
        try:
            r = self.proxy.get("/%2e%2e%2f%2e%2e%2fetc%2fpasswd")
            self.check("Path traversal (encoded) → 403", r, 403)
        except httpx.ConnectError:
            self._skip("Path traversal (encoded) → 403")

    def test_ssrf_blocked(self):
        try:
            payload = {"url": "http://169.254.169.254/latest/meta-data/"}
            r = self.proxy.post("/api/fetch", json=payload)
            self.check("SSRF to metadata endpoint → 403", r, 403)
        except httpx.ConnectError:
            self._skip("SSRF to metadata endpoint → 403")

    def test_canary_blocked(self):
        try:
            r = self.proxy.get("/admin-test")
            self.check("Canary /admin-test → 403", r, 403)
        except httpx.ConnectError:
            self._skip("Canary /admin-test → 403")

        try:
            r = self.proxy.get("/api-debug")
            self.check("Canary /api-debug → 403", r, 403)
        except httpx.ConnectError:
            self._skip("Canary /api-debug → 403")

    def test_header_injection_blocked(self):
        try:
            # CRLF injection attempt in a custom header value
            r = self.proxy.get("/", headers={"X-Custom": "value\r\nX-Injected: evil"})
            self.check("CRLF header injection → 403", r, 403)
        except httpx.LocalProtocolError:
            # httpx (and most HTTP/1.1 clients) reject CRLF in headers before
            # sending — this is correct behaviour. The WAF cannot be tested for
            # this via a standards-compliant client; mark as skip.
            self.results.append(("CRLF header injection → 403", False, "httpx rejected CRLF before sending (client-side validation)"))
            print(f"  [{SKIP}] CRLF header injection → 403  (httpx rejected CRLF client-side)")
        except httpx.ConnectError:
            self._skip("CRLF header injection → 403")

    def test_rate_limit(self, burst: int = 25):
        """Fire `burst` requests quickly; the last ones should hit 429."""
        try:
            statuses = []
            for _ in range(burst):
                r = self.proxy.get("/login")
                statuses.append(r.status_code)

            got_429 = any(s == 429 for s in statuses)
            note = f"fired {burst} requests, statuses: {set(statuses)}"
            self.results.append(("Rate limit burst → 429", got_429, note))
            label = PASS if got_429 else FAIL
            print(f"  [{label}] Rate limit burst → 429  ({note})")
        except httpx.ConnectError:
            self._skip("Rate limit burst → 429")

    def test_api_metrics(self):
        """Dashboard API /api/metrics must return 200."""
        try:
            r = self.api.get("/api/metrics")
            self.check("Dashboard API /api/metrics → 200", r, 200)
        except httpx.ConnectError:
            self._skip("Dashboard API /api/metrics → 200")

    def test_api_rules(self):
        """Dashboard API GET /api/rules must return 200."""
        try:
            r = self.api.get("/api/rules")
            self.check("Dashboard API GET /api/rules → 200", r, 200)
        except httpx.ConnectError:
            self._skip("Dashboard API GET /api/rules → 200")

    # ── CRS rule tests ────────────────────────────────────────────────────────

    def test_crs_scanner_ua_blocked(self):
        """Scanner User-Agents (REQUEST-913) must be blocked by CRS."""
        scanners = [
            ("sqlmap/1.7", "sqlmap UA → 403"),
            ("nikto/2.1.6", "nikto UA → 403"),
            ("arachni/1.5", "arachni UA → 403"),
            ("nmap scripting engine", "nmap UA → 403"),
        ]
        for ua, name in scanners:
            try:
                r = self.proxy.get("/", headers={"User-Agent": ua})
                self.check(f"CRS scanner UA [{ua}] → 403", r, 403)
            except httpx.ConnectError:
                self._skip(name)

    def test_crs_sqli_blocked(self):
        """SQL injection payloads (REQUEST-942) must be blocked by CRS."""
        payloads = [
            ("q", "UNION SELECT username,password FROM users--", "UNION SELECT → 403"),
            ("id", "1; DROP TABLE users--", "DROP TABLE → 403"),
            ("search", "' OR 1=1--", "OR 1=1 → 403"),
            ("cmd", "1 AND (SELECT * FROM (SELECT(SLEEP(1)))a)--", "SLEEP subquery → 403"),
        ]
        for param, value, name in payloads:
            try:
                r = self.proxy.get("/search", params={param: value})
                self.check(f"CRS SQLi [{name}]", r, 403)
            except httpx.ConnectError:
                self._skip(name)

    def test_crs_xss_blocked(self):
        """XSS payloads (REQUEST-941) must be blocked by CRS."""
        payloads = [
            ("<script>alert(document.cookie)</script>", "script tag XSS → 403"),
            ("<img src=x onerror=alert(1)>", "img onerror XSS → 403"),
            ("javascript:alert(1)", "javascript: URI → 403"),
            ("<svg/onload=alert(1)>", "svg onload XSS → 403"),
        ]
        for value, name in payloads:
            try:
                r = self.proxy.get("/page", params={"content": value})
                self.check(f"CRS XSS [{name}]", r, 403)
            except httpx.ConnectError:
                self._skip(name)

    def test_crs_lfi_blocked(self):
        """Local file inclusion / path traversal payloads (REQUEST-930) must be blocked by CRS."""
        paths = [
            ("/../../../../etc/passwd", "LFI /etc/passwd → 403"),
            ("/files?name=../../etc/shadow", "LFI query /etc/shadow → 403"),
            ("/static?file=....//....//etc/passwd", "obfuscated LFI → 403"),
        ]
        for path, name in paths:
            try:
                r = self.proxy.get(path)
                self.check(f"CRS LFI [{name}]", r, 403)
            except httpx.ConnectError:
                self._skip(name)

    def test_crs_rce_blocked(self):
        """Remote code execution / shell injection payloads (REQUEST-932) must be blocked by CRS."""
        payloads = [
            (";cat /etc/passwd", "shell ;cat → 403"),
            ("$(id)", "shell $() → 403"),
            ("|whoami", "shell pipe → 403"),
            ("`uname -a`", "shell backtick → 403"),
        ]
        for value, name in payloads:
            try:
                r = self.proxy.get("/exec", params={"cmd": value})
                self.check(f"CRS RCE [{name}]", r, 403)
            except httpx.ConnectError:
                self._skip(name)

    def test_crs_php_injection_blocked(self):
        """PHP code injection payloads (REQUEST-933) must be blocked by CRS."""
        payloads = [
            ("<?php echo shell_exec($_GET['cmd']); ?>", "PHP open tag → 403"),
            ("eval(base64_decode('dW5hbWUgLWE='))", "PHP eval+b64 → 403"),
            ("system('id')", "PHP system() → 403"),
        ]
        for value, name in payloads:
            try:
                r = self.proxy.get("/page", params={"tpl": value})
                self.check(f"CRS PHP [{name}]", r, 403)
            except httpx.ConnectError:
                self._skip(name)

    def test_crs_clean_request_passes(self):
        """A benign request with a normal UA must not be falsely blocked by CRS."""
        try:
            r = self.proxy.get(
                "/api/products",
                params={"category": "electronics", "page": "1"},
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )
            ok = r.status_code < 400 or r.status_code == 404
            note = f"got {r.status_code}"
            self.results.append(("CRS clean request → pass", ok, note))
            label = PASS if ok else FAIL
            print(f"  [{label}] CRS clean request → pass  ({note})")
        except httpx.ConnectError:
            self._skip("CRS clean request → pass")

    # ── Geo-blocking tests ─────────────────────────────────────────────────────

    def test_geo_header_blocked(self):
        """Requests with a blocked country in CF-IPCountry header must be blocked."""
        blocked_codes = ["KP", "IR", "CU"]
        for code in blocked_codes:
            try:
                r = self.proxy.get("/", headers={"CF-IPCountry": code})
                # Only FAIL if actually blocked (403) — if blocked_countries is empty
                # in config the WAF will pass through, so accept both outcomes.
                note = f"got {r.status_code}"
                self.results.append((f"Geo block [{code}] via CF-IPCountry header", r.status_code == 403, note))
                label = PASS if r.status_code == 403 else FAIL
                print(f"  [{label}] Geo block [{code}] via CF-IPCountry header  ({note})")
            except httpx.ConnectError:
                self._skip(f"Geo block [{code}] via CF-IPCountry header")

    def test_geo_header_allowed(self):
        """Requests with a non-blocked country code must pass through."""
        try:
            r = self.proxy.get("/", headers={"CF-IPCountry": "US"})
            ok = r.status_code != 403
            note = f"got {r.status_code}"
            self.results.append(("Geo allow [US] via CF-IPCountry header", ok, note))
            label = PASS if ok else FAIL
            print(f"  [{label}] Geo allow [US] via CF-IPCountry header  ({note})")
        except httpx.ConnectError:
            self._skip("Geo allow [US] via CF-IPCountry header")

    # ── GetCountry() GRL tests (GeoBlockVN rule — hardcoded, not config) ──────

    def test_getcountry_vn_blocked(self):
        """CF-IPCountry: VN must be blocked by the GeoBlockVN GRL rule."""
        try:
            r = self.proxy.get("/", headers={"CF-IPCountry": "VN"})
            note = f"got {r.status_code}"
            ok = r.status_code == 403
            self.results.append(("GetCountry() VN → blocked (CF-IPCountry)", ok, note))
            label = PASS if ok else FAIL
            print(f"  [{label}] GetCountry() VN → blocked (CF-IPCountry)  ({note})")
        except httpx.ConnectError:
            self._skip("GetCountry() VN → blocked (CF-IPCountry)")

    def test_getcountry_header_variants(self):
        """Alternative geo headers (X-Country, X-GeoIP-Country, X-Geo-Country) must
        resolve VN and trigger GeoBlockVN."""
        headers_to_test = [
            ("X-Country", "VN"),
            ("X-GeoIP-Country", "VN"),
            ("X-Geo-Country", "VN"),
        ]
        for hdr, code in headers_to_test:
            name = f"GetCountry() VN → blocked ({hdr})"
            try:
                r = self.proxy.get("/", headers={hdr: code})
                note = f"got {r.status_code}"
                ok = r.status_code == 403
                self.results.append((name, ok, note))
                label = PASS if ok else FAIL
                print(f"  [{label}] {name}  ({note})")
            except httpx.ConnectError:
                self._skip(name)

    def test_getcountry_non_vn_passes(self):
        """A country that is neither VN nor in blocked_countries must pass through."""
        try:
            r = self.proxy.get("/", headers={"CF-IPCountry": "JP"})
            note = f"got {r.status_code}"
            ok = r.status_code != 403
            self.results.append(("GetCountry() JP → allowed", ok, note))
            label = PASS if ok else FAIL
            print(f"  [{label}] GetCountry() JP → allowed  ({note})")
        except httpx.ConnectError:
            self._skip("GetCountry() JP → allowed")

    # ── skip helper ──────────────────────────────────────────────────────────
    def _skip(self, name: str):
        self.results.append((name, False, "WAF not running"))
        print(f"  [{SKIP}] {name}  (WAF not running)")

    # ── run all ──────────────────────────────────────────────────────────────
    def run_all(self):
        print(f"\n{BOLD}  mini-waf proxy integration tests{RESET}\n")

        self.test_passthrough()
        self.test_sqli_blocked()
        self.test_sqli_body_blocked()
        self.test_xss_blocked()
        self.test_path_traversal_blocked()
        self.test_path_traversal_encoded_blocked()
        self.test_ssrf_blocked()
        self.test_canary_blocked()
        self.test_header_injection_blocked()
        self.test_rate_limit()
        self.test_api_metrics()
        self.test_api_rules()

        # ── CRS rule tests ────────────────────────────────────────────────────
        self.test_crs_scanner_ua_blocked()
        self.test_crs_sqli_blocked()
        self.test_crs_xss_blocked()
        self.test_crs_lfi_blocked()
        self.test_crs_rce_blocked()
        self.test_crs_php_injection_blocked()
        self.test_crs_clean_request_passes()

        # ── Geo-blocking tests (geo_blocked() — config-driven) ───────────────
        self.test_geo_header_blocked()
        self.test_geo_header_allowed()

        # ── GetCountry() tests (GeoBlockVN rule — hardcoded GRL) ─────────────
        self.test_getcountry_vn_blocked()
        self.test_getcountry_header_variants()
        self.test_getcountry_non_vn_passes()

        # ── summary ──────────────────────────────────────────────────────────
        total   = len(self.results)
        passed  = sum(1 for _, ok, _ in self.results if ok)
        skipped = sum(1 for _, _, note in self.results if "not running" in note)
        failed  = total - passed - skipped

        print(f"\n  {BOLD}Results:{RESET} "
              f"{GREEN}{passed} passed{RESET}  "
              f"{RED}{failed} failed{RESET}  "
              f"{YELLOW}{skipped} skipped{RESET}  "
              f"({total} total)\n")

        return failed == 0


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="mini-waf proxy REST test client")
    parser.add_argument("--proxy", default="http://127.0.0.1:8111",
                        help="WAF proxy base URL (default: http://127.0.0.1:8111)")
    parser.add_argument("--api",   default="http://127.0.0.1:8112",
                        help="Dashboard API base URL (default: http://127.0.0.1:8112)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print response bodies")
    args = parser.parse_args()

    client = TestClient(proxy_base=args.proxy, api_base=args.api, verbose=args.verbose)
    try:
        ok = client.run_all()
    finally:
        client.close()

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
