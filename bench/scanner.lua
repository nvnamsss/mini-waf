-- Scanner UA flood: every request uses a known bad User-Agent.
-- Tests the scanner-detection (REQUEST-913) CRS rule path.
--
-- Usage:
--   wrk -t4 -c100 -d30s --latency -s bench/scanner.lua http://127.0.0.1:8111

local agents = {
    "Nikto/2.1.6",
    "sqlmap/1.7 (https://sqlmap.org)",
    "Nmap Scripting Engine",
    "masscan/1.3",
    "zgrab/0.x",
}

local i = 0

request = function()
    i = i + 1
    local ua = agents[(i % #agents) + 1]
    wrk.headers["User-Agent"] = ua
    return wrk.format("GET", "/", wrk.headers, nil)
end
