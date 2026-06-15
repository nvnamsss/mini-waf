-- Baseline: clean GET requests — no attack patterns.
-- Representative of normal legitimate traffic hitting the WAF.
--
-- Usage (WAF must be running on :8111):
--   wrk -t4 -c100 -d30s --latency -s bench/clean.lua http://127.0.0.1:8111

wrk.method = "GET"
wrk.path   = "/api/users"
wrk.headers["Accept"] = "application/json"
