CARGO        := $(HOME)/.cargo/bin/cargo
RUSTUP       := $(HOME)/.cargo/bin/rustup
WAF_CONFIG   ?= config/waf.toml
RELEASE_BIN  := target/release/waf
DEBUG_BIN    := target/debug/waf
WRK          ?= wrk
WAF_HOST     ?= http://127.0.0.1:8111
# wrk tunables — override on the command line: make bench-clean WRK_THREADS=8
WRK_THREADS  ?= 4
WRK_CONNS    ?= 200
WRK_DURATION ?= 30s

GO_FTW       ?= $(shell go env GOPATH)/bin/go-ftw
FTW_DIR      ?= coreruleset/tests/regression/tests
FTW_CONFIG   ?= .ftw.yaml

.PHONY: all build build-release check clean run run-release \
        test-unit test-integration test-ftw test-ftw-crs \
        backend-python backend-go backend-java \
        fmt lint dashboard-install dashboard-build dashboard-dev install-rust crs-install \
        bench-clean bench-sqli bench-xss bench-scanner bench-mixed bench-all bench-crs

# ─── Default ─────────────────────────────────────────────────────────────────
all: build

# ─── Rust toolchain ──────────────────────────────────────────────────────────
install-rust:
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
	$(RUSTUP) toolchain install stable

# ─── OWASP CRS ───────────────────────────────────────────────────────────────
# Copy all REQUEST-*.conf and *.data files from the bundled coreruleset/ clone
# into config/rules/crs/ and config/rules/data/.  Re-run after `git submodule
# update` when you want to pick up a new CRS release.
crs-install:
	cp coreruleset/rules/REQUEST-*.conf config/rules/crs/
	cp coreruleset/rules/*.data config/rules/data/
	@echo "CRS rules installed ($(shell ls config/rules/crs/*.conf | wc -l | tr -d ' ') conf, \
$(shell ls config/rules/data/*.data | wc -l | tr -d ' ') data files)"

# ─── Build ───────────────────────────────────────────────────────────────────
build:
	$(CARGO) build --workspace

build-release:
	$(CARGO) build --workspace --release

# ─── Check (no codegen, fast) ────────────────────────────────────────────────
check:
	$(CARGO) check --workspace

# ─── Run ─────────────────────────────────────────────────────────────────────
run: build
	$(DEBUG_BIN) run --config $(WAF_CONFIG)

run-release: build-release
	$(RELEASE_BIN) run --config $(WAF_CONFIG)

# ─── Test ────────────────────────────────────────────────────────────────────
test-unit:
	$(CARGO) test --workspace

test-verbose:
	$(CARGO) test --workspace -- --nocapture

test-integration:
	python tests/rest_client.py --proxy http://localhost:8111 --api http://localhost:8112

# ─── go-ftw accuracy tests ───────────────────────────────────────────────────
# Requires: WAF running on :8111, backend running on :3000
# Install go-ftw: go install github.com/coreruleset/go-ftw@latest
#
# Override test dir:  make test-ftw FTW_DIR=tests/ftw
# Run a single file:  make test-ftw FTW_DIR=tests/ftw/sqli.yaml
test-ftw:
	@command -v $(GO_FTW) >/dev/null 2>&1 || \
	  { echo "go-ftw not found — install with: go install github.com/coreruleset/go-ftw@latest"; exit 1; }
	$(GO_FTW) --config $(FTW_CONFIG) run -d $(FTW_DIR)

# Run all 319 OWASP CRS regression tests in cloud mode
# Transforms log-based CRS tests into cloud-mode (HTTP-status-based) format on each run
# Requires: WAF running on :8111, backend running on :3000
test-ftw-crs:
	@command -v $(GO_FTW) >/dev/null 2>&1 || \
	  { echo "go-ftw not found — install with: go install github.com/coreruleset/go-ftw@latest"; exit 1; }
	python3 tests/ftw/transform_crs.py
	$(GO_FTW) --config $(FTW_CONFIG) run -d tests/ftw/crs

# ─── Lint / Format ───────────────────────────────────────────────────────────
fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

# ─── Dashboard (Node.js / TypeScript) ────────────────────────────────────────
dashboard-install:
	cd dashboard && npm install

dashboard-build: dashboard-install
	cd dashboard && npm run build

dashboard-dev: dashboard-install
	cd dashboard && npm run dev

# ─── Backends (test upstreams, all listen on :3000) ─────────────────────────
backend-python:
	cd backends/python-fastapi && pip install -q -r requirements.txt && python main.py

backend-go:
	cd backends/go-gin && go mod tidy && go run .

backend-java:
	cd backends/java-spring && mvn spring-boot:run

# ─── Clean ───────────────────────────────────────────────────────────────────
clean:
	$(CARGO) clean
	rm -rf dashboard/dist dashboard/node_modules

# ─── Combined dev target (proxy + dashboard) ─────────────────────────────────
dev: build dashboard-install
	@echo "Starting WAF proxy (debug)..."
	$(DEBUG_BIN) run --config $(WAF_CONFIG) &
	@echo "Starting dashboard dev server..."
	cd dashboard && npm run dev

# ─── wrk HTTP benchmarks ─────────────────────────────────────────────────────
# The WAF (and ideally a backend) must be running before invoking these.
# Start the WAF:   make run-release
# Start a backend: make backend-go   (optional; WAF returns 502 if absent)
#
# Tune via env:
#   make bench-clean WRK_THREADS=8 WRK_CONNS=500 WRK_DURATION=60s
#   make bench-all   WAF_HOST=http://10.0.0.1:8111

_wrk_check:
	@command -v $(WRK) >/dev/null 2>&1 || \
	  { echo "wrk not found — install with: brew install wrk"; exit 1; }

bench-clean: _wrk_check
	@echo "── clean traffic (GET /api/users) ──────────────────────────────"
	$(WRK) -t$(WRK_THREADS) -c$(WRK_CONNS) -d$(WRK_DURATION) --latency \
	  -s bench/clean.lua $(WAF_HOST)

bench-sqli: _wrk_check
	@echo "── SQLi flood (expect 403 on every request) ─────────────────────"
	$(WRK) -t$(WRK_THREADS) -c$(WRK_CONNS) -d$(WRK_DURATION) --latency \
	  -s bench/sqli.lua $(WAF_HOST)

bench-xss: _wrk_check
	@echo "── XSS flood (expect 403 on every request) ──────────────────────"
	$(WRK) -t$(WRK_THREADS) -c$(WRK_CONNS) -d$(WRK_DURATION) --latency \
	  -s bench/xss.lua $(WAF_HOST)

bench-scanner: _wrk_check
	@echo "── Scanner UA flood (expect 403 on every request) ───────────────"
	$(WRK) -t$(WRK_THREADS) -c$(WRK_CONNS) -d$(WRK_DURATION) --latency \
	  -s bench/scanner.lua $(WAF_HOST)

bench-mixed: _wrk_check
	@echo "── Mixed traffic (~70% clean / 30% attacks) ─────────────────────"
	$(WRK) -t$(WRK_THREADS) -c$(WRK_CONNS) -d$(WRK_DURATION) --latency \
	  -s bench/mixed.lua $(WAF_HOST)

bench-all: _wrk_check bench-clean bench-sqli bench-xss bench-scanner bench-mixed

# ─── Criterion micro-benchmarks ──────────────────────────────────────────────
# No running WAF required — benchmarks run in-process against the engine.

# Benchmark the CRS evaluator in isolation (7 scenarios: clean, sqli, xss, …).
# Results are written to target/criterion/crs/.
bench-crs:
	$(CARGO) bench -p waf-engine -- crs
