-- Mixed traffic: randomly picks either a clean request or one of several
-- attack payloads on each request.  Approximates realistic traffic mix.
-- ~70% clean, ~10% SQLi, ~10% XSS, ~5% path traversal, ~5% scanner UA.
--
-- Usage:
--   wrk -t4 -c100 -d30s --latency -s bench/mixed.lua http://127.0.0.1:8111

math.randomseed(os.time())

local scenarios = {
    -- weight 7: clean
    { w=7, method="GET", path="/api/users",                      ua=nil },
    { w=7, method="GET", path="/api/products",                   ua=nil },
    { w=7, method="GET", path="/",                               ua=nil },
    -- weight 1: SQLi
    { w=1, method="GET", path="/search?q=1%27%20OR%201%3D1--",   ua=nil },
    { w=1, method="GET", path="/search?id=1%20UNION%20SELECT%201,2,3--", ua=nil },
    -- weight 1: XSS
    { w=1, method="GET", path="/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", ua=nil },
    { w=1, method="GET", path="/comment?text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", ua=nil },
    -- weight 0.5: path traversal
    { w=1, method="GET", path="/../../../etc/passwd",            ua=nil },
    -- weight 0.5: scanner UA
    { w=1, method="GET", path="/",    ua="Nikto/2.1.6" },
}

-- Build lookup table weighted by w
local pool = {}
for _, s in ipairs(scenarios) do
    for _ = 1, s.w do
        pool[#pool+1] = s
    end
end

request = function()
    local s = pool[math.random(#pool)]
    local h = "Host: 127.0.0.1:8111\r\nAccept: application/json\r\n"
    if s.ua then
        h = h .. "User-Agent: " .. s.ua .. "\r\n"
    end
    return wrk.format(s.method, s.path, nil, nil)
end
