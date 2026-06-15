-- SQLi attack: every request carries a classic SQL injection payload.
-- Expects the WAF to return 403 (blocked).  Measures throughput on the
-- block path — this exercises the CRS + RETE "early exit" code path.
--
-- Usage:
--   wrk -t4 -c100 -d30s --latency -s bench/sqli.lua http://127.0.0.1:8111

wrk.method = "GET"
wrk.path   = "/search?q=1%27%20OR%201%3D1--"   -- q=1' OR 1=1--  (URL-encoded)
wrk.headers["Accept"] = "application/json"
