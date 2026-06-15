#!/usr/bin/env python3
"""Transform CRS regression tests (log-based) → cloud-mode FTW tests (status-based).

Reads YAML files from coreruleset/tests/regression/tests/ and writes
cloud-mode-compatible versions to tests/ftw/crs/.

Transformations:
  - output.log.expect_ids   → output.status: 403  (WAF should block)
  - output.log.no_expect_ids → output.status: [200, 404]  (WAF should pass)
  - output.status: N        → kept as-is
  - input.dest_addr/port/protocol → overridden to local WAF
  - input.uri == "/post"    → remapped to /api/echo (accepts POST)

Usage:
  python tests/ftw/transform_crs.py
"""
import os
import sys
import shutil
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(REPO_ROOT, "coreruleset/tests/regression/tests")
DST = os.path.join(REPO_ROOT, "tests/ftw/crs")


def cloud_output(out):
    """Convert a log-based output dict to an HTTP-status-based one."""
    if out is None:
        return {"status": [200, 404]}
    # Already has explicit status with no log dependency — keep it
    if "status" in out and "log" not in out:
        return {"status": out["status"]}
    log = out.get("log", {})
    if "expect_ids" in log:
        return {"status": 403}
    if "no_expect_ids" in log:
        return {"status": [200, 404]}
    # Fallback
    return {"status": [200, 404]}


def transform(data):
    for test in (data or {}).get("tests", []):
        for stage in test.get("stages", []):
            inp = stage.get("input", {})
            inp["dest_addr"] = "127.0.0.1"
            inp["port"] = 8111
            inp["protocol"] = "http"
            # Remap /post → /api/echo (our backend's POST-accepting endpoint)
            if inp.get("uri") == "/post":
                inp["uri"] = "/api/echo"
            # Normalise Host header to avoid 920350 (Host-as-IP) rule triggering
            headers = inp.get("headers", {})
            if isinstance(headers, dict) and headers.get("Host", "").replace(".", "").isdigit():
                headers["Host"] = "localhost"
            stage["output"] = cloud_output(stage.get("output"))
    return data


def main():
    if not os.path.isdir(SRC):
        sys.exit(f"CRS source dir not found: {SRC}\n"
                 "Run: git submodule update --init coreruleset")

    if os.path.exists(DST):
        shutil.rmtree(DST)

    n_ok = n_skip = 0
    for dirpath, _dirs, files in os.walk(SRC):
        for fn in sorted(files):
            if not fn.endswith((".yaml", ".yml")):
                continue
            src = os.path.join(dirpath, fn)
            rel = os.path.relpath(src, SRC)
            dst = os.path.join(DST, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                with open(src, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if not isinstance(data, dict) or "tests" not in data:
                    n_skip += 1
                    continue
                transform(data)
                with open(dst, "w", encoding="utf-8") as f:
                    yaml.dump(data, f, allow_unicode=True, sort_keys=False,
                              default_flow_style=False)
                n_ok += 1
            except Exception as exc:
                print(f"  skip {rel}: {exc}", file=sys.stderr)
                n_skip += 1

    print(f"Transformed {n_ok} files → {os.path.relpath(DST, REPO_ROOT)}/  "
          f"(skipped {n_skip})")


if __name__ == "__main__":
    main()
