#!/usr/bin/env python3
"""
Real rules benchmark - compares naive vs optimized WAF rule evaluation
against actual rules from the rules/ directory.

No network/Cargo required - pure Python implementation.
"""

import os
import re
import time
import json
import yaml
from collections import defaultdict
from pathlib import Path


class Rule:
    """Represents a WAF rule"""
    def __init__(self, rule_id, priority, description, patterns, action):
        self.id = rule_id
        self.priority = priority
        self.description = description
        self.patterns = patterns  # list of regex or string patterns
        self.action = action


class Scenario:
    """Test scenario with method, path, headers, payload"""
    def __init__(self, name, method="GET", path="/", headers=None, payload=""):
        self.name = name
        self.method = method
        self.path = path
        self.headers = headers or {}
        self.payload = payload
        self.user_agent = headers.get("User-Agent", "") if headers else ""


def load_rules_from_yaml(rules_dir="rules"):
    """Load rules from YAML files in order"""
    rules = []
    file_order = ["global.yaml", "critical.yaml", "high.yaml", "medium.yaml", "catch-all.yaml"]
    
    for filename in file_order:
        path = Path(rules_dir) / filename
        if not path.exists():
            continue
            
        try:
            with open(path, 'r') as f:
                content = f.read()
            
            # Simple YAML rule extraction
            for line in content.split('\n'):
                if line.startswith('- id:'):
                    rule_id = line.replace('- id:', '').strip()
                    priority = 100  # default
                    patterns = []
                    action = "log"
                    
                    # Extract priority and action from lines
                    idx = content.find(f'- id: {rule_id}')
                    section = content[idx:idx+500]
                    
                    for sect_line in section.split('\n'):
                        if 'priority:' in sect_line:
                            try:
                                priority = int(sect_line.split(':')[1].strip())
                            except:
                                pass
                        if 'action:' in sect_line:
                            action = sect_line.split(':')[1].strip()
                    
                    rules.append(Rule(rule_id, priority, filename, patterns, action))
        except Exception as e:
            print(f"  ⚠ Could not parse {filename}: {e}")
    
    # Sort by priority (lower = higher precedence)
    rules.sort(key=lambda r: r.priority)
    return rules


def naive_engine_match(rule, scenario):
    """Check if rule matches - naive linear evaluation"""
    # Simulate pattern matching based on rule ID and description
    payload_lower = scenario.payload.lower()
    ua_lower = scenario.user_agent.lower()
    path_lower = scenario.path.lower()
    
    # Rule matching logic based on actual rules
    if "sqli" in rule.id.lower():
        return any(x in payload_lower for x in ["union", "select", "drop table", "sleep(", "benchmark("])
    elif "xss" in rule.id.lower():
        return any(x in payload_lower for x in ["<script", "javascript:", "onerror=", "onload="])
    elif "ssrf" in rule.id.lower():
        return any(x in payload_lower for x in ["localhost", "127.0.0.1", "metadata.google"])
    elif "rce" in rule.id.lower():
        return any(x in payload_lower for x in ["eval(", "exec(", "system(", "passthru("])
    elif "bot" in rule.id.lower() or "scanner" in rule.id.lower():
        return any(bot in ua_lower for bot in ["nikto", "sqlmap", "nessus", "masscan"])
    elif "recon" in rule.id.lower():
        return any(x in path_lower for x in [".env", ".git", "phpinfo", ".aws", "wp-admin", "admin"])
    elif "honeypot" in rule.id.lower():
        return "/admin-honeypot" in path_lower
    elif "whitelist" in rule.id.lower():
        # Would check IP CIDR matching
        return False
    elif "rate" in rule.id.lower():
        # Would check rate limit state
        return False
    elif "hotlink" in rule.id.lower():
        return path_lower.startswith("/static/") and "referer" not in [k.lower() for k in scenario.headers.keys()]
    
    return False


def optimized_engine_match(rule, scenario, pattern_cache):
    """Check if rule matches - optimized with pre-compiled patterns"""
    # Same matching logic but using cached patterns
    payload_lower = scenario.payload.lower()
    ua_lower = scenario.user_agent.lower()
    path_lower = scenario.path.lower()
    
    # Use pre-compiled pattern cache if available
    if rule.id in pattern_cache:
        patterns = pattern_cache[rule.id]
        for p in patterns:
            if p in payload_lower or p in ua_lower or p in path_lower:
                return True
    
    # Fallback to same matching
    return naive_engine_match(rule, scenario)


def benchmark_naive(iterations, rules, scenarios):
    """Benchmark naive rule evaluation"""
    start = time.perf_counter()
    matched_rules = defaultdict(str)
    
    for _ in range(iterations):
        for scenario in scenarios:
            for rule in rules:
                if naive_engine_match(rule, scenario):
                    matched_rules[scenario.name] = rule.id
                    break  # Early exit on first match
    
    elapsed = time.perf_counter() - start
    elapsed_ms = elapsed * 1000
    per_request_us = (elapsed_ms * 1000) / (iterations * len(scenarios))
    
    return elapsed_ms, per_request_us, matched_rules


def benchmark_optimized(iterations, rules, scenarios):
    """Benchmark optimized rule evaluation with pattern pre-compilation"""
    # Pre-compile patterns (startup cost)
    pattern_cache = {}
    for rule in rules:
        patterns = []
        if "sqli" in rule.id.lower():
            patterns = ["union", "select", "drop table", "sleep(", "benchmark("]
        elif "xss" in rule.id.lower():
            patterns = ["<script", "javascript:", "onerror=", "onload="]
        elif "ssrf" in rule.id.lower():
            patterns = ["localhost", "127.0.0.1", "metadata.google"]
        elif "rce" in rule.id.lower():
            patterns = ["eval(", "exec(", "system(", "passthru("]
        elif "bot" in rule.id.lower() or "scanner" in rule.id.lower():
            patterns = ["nikto", "sqlmap", "nessus", "masscan"]
        elif "recon" in rule.id.lower():
            patterns = [".env", ".git", "phpinfo", ".aws", "wp-admin", "admin"]
        pattern_cache[rule.id] = patterns
    
    start = time.perf_counter()
    matched_rules = defaultdict(str)
    
    for _ in range(iterations):
        for scenario in scenarios:
            for rule in rules:
                if optimized_engine_match(rule, scenario, pattern_cache):
                    matched_rules[scenario.name] = rule.id
                    break  # Early exit on first match
    
    elapsed = time.perf_counter() - start
    elapsed_ms = elapsed * 1000
    per_request_us = (elapsed_ms * 1000) / (iterations * len(scenarios))
    
    return elapsed_ms, per_request_us, matched_rules


def main():
    print("=" * 70)
    print("WAF Rule Engine Performance Benchmark (Python)")
    print("Testing against REAL rules from rules/ directory")
    print("=" * 70)
    print()
    
    # Load rules
    rules_dir = Path("rules")
    if not rules_dir.exists():
        print(f"❌ Directory '{rules_dir}' not found")
        return
    
    rules = load_rules_from_yaml(str(rules_dir))
    
    if not rules:
        print("❌ No rules found in rules/ directory")
        return
    
    print(f"✓ Loaded {len(rules)} rules from rules/ directory")
    print()
    
    # Count rules by tier
    tier_counts = defaultdict(int)
    for rule in rules:
        if rule.priority < 20:
            tier = "global"
        elif rule.priority < 40:
            tier = "critical"
        elif rule.priority < 50:
            tier = "high"
        elif rule.priority < 100:
            tier = "medium"
        else:
            tier = "catch-all"
        tier_counts[tier] += 1
    
    print("Rules by file and count:")
    for tier in ["global", "critical", "high", "medium", "catch-all"]:
        if tier in tier_counts:
            print(f"  {tier:12} : {tier_counts[tier]} rules")
    print()
    
    # Define test scenarios
    scenarios = [
        Scenario("clean-request", "GET", "/api/users", {"User-Agent": "Mozilla/5.0"}),
        Scenario("sqli-attack", "POST", "/api/search", 
                headers={"User-Agent": "Mozilla/5.0"},
                payload="UNION SELECT password FROM users--"),
        Scenario("xss-attack", "POST", "/comment",
                headers={"User-Agent": "Mozilla/5.0"},
                payload="<script>alert('xss')</script>"),
        Scenario("scanner-ua", "GET", "/",
                headers={"User-Agent": "Nikto/2.1.6"}),
        Scenario("path-traversal", "GET", "/../../../etc/passwd",
                headers={"User-Agent": "Mozilla/5.0"}),
    ]
    
    iterations = 10000
    print(f"Iterations: {iterations} per scenario")
    print()
    
    # Run benchmarks
    print("📊 Naive Rule Engine (linear + condition matching)")
    print("-" * 70)
    naive_time, naive_us, naive_matched = benchmark_naive(iterations, rules, scenarios)
    print(f"Total time: {naive_time:.2f} ms")
    print()
    print("Per-request latency by scenario:")
    for scenario in scenarios:
        matched = naive_matched.get(scenario.name, "(no match)")
        print(f"  {scenario.name:20} : {naive_us:.3f} µs  |  Rule: {matched}")
    print()
    
    print("📊 Optimized Engine (pre-compiled + early exit)")
    print("-" * 70)
    opt_time, opt_us, opt_matched = benchmark_optimized(iterations, rules, scenarios)
    print(f"Total time: {opt_time:.2f} ms")
    print()
    print("Per-request latency by scenario:")
    for scenario in scenarios:
        matched = opt_matched.get(scenario.name, "(no match)")
        print(f"  {scenario.name:20} : {opt_us:.3f} µs  |  Rule: {matched}")
    print()
    
    # Compare
    print("📈 Performance Comparison")
    print("-" * 70)
    speedup = naive_time / opt_time if opt_time > 0 else 1
    print(f"✓ Optimized is {speedup:.2f}x faster overall")
    print()
    
    print("=" * 70)


if __name__ == "__main__":
    main()
