-- XSS attack: every request carries an XSS payload in the query string.
-- Expects 403. Tests the XSS detection hot path end-to-end through the proxy.
--
-- Usage:
--   wrk -t4 -c100 -d30s --latency -s bench/xss.lua http://127.0.0.1:8111

wrk.method = "GET"
wrk.path   = "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"   -- <script>alert(1)</script>
wrk.headers["Accept"] = "application/json"
