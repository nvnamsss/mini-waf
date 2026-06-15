#!/usr/bin/env python3
"""Find and display a specific CRS test by ID.

Usage:
  python tests/ftw/find_test.py 920201-1
  python tests/ftw/find_test.py 942100        # show all tests for rule
  python tests/ftw/find_test.py 920201-1 --cloud  # show cloud-mode (transformed) version
"""
import sys
import os
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CRS_SRC = os.path.join(REPO_ROOT, "coreruleset/tests/regression/tests")
CRS_CLOUD = os.path.join(REPO_ROOT, "tests/ftw/crs")


def find_yaml(root, rule_id):
    target = f"{rule_id}.yaml"
    for dirpath, _dirs, files in os.walk(root):
        if target in files:
            return os.path.join(dirpath, target)
    return None


def show_test(data, test_id=None):
    rule_id = data.get("rule_id", "?")
    meta = data.get("meta", {})
    if meta.get("description"):
        print(f"  desc: {meta['description'].strip()}")
    tests = data.get("tests", [])
    for t in tests:
        if test_id is not None and t.get("test_id") != test_id:
            continue
        print(f"\n[{rule_id}-{t['test_id']}] {t.get('desc', '')}")
        for i, stage in enumerate(t.get("stages", []), 1):
            inp = stage.get("input", {})
            out = stage.get("output", {})
            print(f"  Input:")
            print(f"    method: {inp.get('method', 'GET')}")
            print(f"    uri:    {inp.get('uri', '/')}")
            if inp.get("data"):
                print(f"    data:   {inp['data']}")
            hdrs = inp.get("headers", {})
            for k, v in (hdrs.items() if isinstance(hdrs, dict) else []):
                print(f"    {k}: {v}")
            print(f"  Output: {out}")
    if test_id is not None and not any(t.get("test_id") == test_id for t in tests):
        print(f"  (test_id {test_id} not found; available: {[t['test_id'] for t in tests]})")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    use_cloud = "--cloud" in sys.argv

    if not args:
        print("Usage: find_test.py <rule_id>[-<test_id>] [--cloud]")
        print("  e.g. find_test.py 920201-1")
        print("  e.g. find_test.py 942100 --cloud")
        sys.exit(1)

    spec = args[0]
    if "-" in spec:
        parts = spec.rsplit("-", 1)
        rule_id = int(parts[0])
        test_id = int(parts[1])
    else:
        rule_id = int(spec)
        test_id = None

    root = CRS_CLOUD if use_cloud else CRS_SRC
    label = "cloud" if use_cloud else "source"

    path = find_yaml(root, rule_id)
    if path is None:
        if use_cloud:
            print(f"Not found in cloud tests. Try running: make test-ftw-crs (to regenerate)")
        else:
            print(f"Rule {rule_id} not found in {root}")
        sys.exit(1)

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rel = os.path.relpath(path, REPO_ROOT)
    print(f"File ({label}): {rel}")
    show_test(data, test_id)


if __name__ == "__main__":
    main()
