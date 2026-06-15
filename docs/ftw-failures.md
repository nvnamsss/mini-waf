# CRS go-ftw Failure Analysis

This document tracks the 26 `make test-ftw-crs` test failures that remain after setting
`detection_paranoia_level` / `blocking_paranoia_level` from 1 → 2 (which resolved 33 of the
original 59 failures).  Each group explains the root cause and the fix needed.

---

## What we already fixed

| Change | File | Effect |
|--------|------|--------|
| `detection_paranoia_level = 2` | `crates/waf-engine/src/rules/crs/tx.rs` | Unlocked all PL2 rules, resolved 33 tests |
| `blocking_paranoia_level = 2`  | same | Consistent blocking at PL2 |

---

## Remaining 26 failures by root cause

### Group 1 — Paranoia-level gate (11 tests)

Rules at PL3 or PL4 are still skipped because `detection_paranoia_level = 2`.

| Test | Rule | PL | File | Gate line |
|------|------|----|------|-----------|
| 920202-1 | 920202 | 4 | REQUEST-920 | after `@lt 4` @ line 1848 |
| 920202-2 | 920202 | 4 | REQUEST-920 | same |
| 921220-1 | 921220 | 3 | REQUEST-921 | after `@lt 3` @ line 436 |
| 921230-1 | 921230 | 3 | REQUEST-921 | same |
| 932350-2 | 932350 | 3 | REQUEST-932 | after `@lt 3` @ line 1841 |
| 932350-3 | 932350 | 3 | REQUEST-932 | same |
| 932331-1 | 932331 | 3 | REQUEST-932 | same |
| 932331-2 | 932331 | 3 | REQUEST-932 | same |
| 933111-5 | 933111 | 3 | REQUEST-933 | after `@lt 3` @ line 744 |

**Fix**: raise `detection_paranoia_level` (and `blocking_paranoia_level`) to 3 in `tx.rs`.
Note: PL3 increases false-positive rate; evaluate against benign-traffic tests before merging.
For rule 920202 (PL4) an additional bump to 4 is needed.

---

### Group 2 — `@validateUtf8Encoding` always passes (4 tests)

**Tests**: 920250-1, 920250-2, 920250-3, 920250-4

**Rule 920250** (PL1):

```
SecRule TX:CRS_VALIDATE_UTF8_ENCODING "@eq 1" "chain"
  SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@validateUtf8Encoding" "t:none,..."
```

The rule fires when an ARGS value contains invalid UTF-8 percent-encoded sequences
(e.g. `%c0%af`, `%F5%80%BF%BF`).

**Root cause**: `extract_values` always calls `pct_decode()` on ARGS values at extraction time.
`pct_decode` uses `String::from_utf8_lossy`, which replaces invalid UTF-8 byte sequences with
U+FFFD (the Unicode replacement character, `\u{FFFD}`).  By the time
`is_valid_utf8_encoded` runs in `operator.rs`, the `%XX` sequences are gone; the function
scans the string for `%XX` patterns and finds none → returns `true` (valid) → rule does not
fire.

**Fix** (`crates/waf-engine/src/rules/crs/operator.rs`): replace the body of
`is_valid_utf8_encoded` to detect the replacement char left by lossy decoding:

```rust
fn is_valid_utf8_encoded(value: &str) -> bool {
    // pct_decode() already ran; invalid UTF-8 sequences are now U+FFFD.
    !value.contains('\u{FFFD}')
}
```

---

### Group 3 — `&ARGS` collection-count target not supported (1 test)

**Test**: 920380-1

**Rule 920380** (PL1):

```
SecRule &TX:MAX_NUM_ARGS "@eq 1" "chain"    # guard: max_num_args is configured
  SecRule &ARGS "@gt %{tx.max_num_args}"    # actual args count > limit
```

The chain head (`&TX:MAX_NUM_ARGS`) is supported (the parser handles `&TX:` prefixes).
The chain member (`&ARGS`) is not: the parser's `parse_one_target` only handles
`&TX:<var>` and `&REQUEST_HEADERS:<name>`; bare `&ARGS` falls through to the
`tok.starts_with('&')` early-return and is silently dropped.

Additionally, the operator `@gt %{tx.max_num_args}` uses a TX variable reference as the RHS,
which requires `CrsOperator::GtTxRef` rather than the literal `Gt`.

**Fix**:
1. Add `CrsTarget::ArgsCount` in `target.rs`; return the total argument count as a string.
2. Handle `"&ARGS"` in `parse_one_target` in `parser.rs` → `CrsTarget::ArgsCount`.
3. `@gt %{tx.VAR}` already parses to `CrsOperator::GtTxRef` (confirmed in `parser.rs`) — no
   extra work needed there.

---

### Group 4 — Missing `t:escapeSeqDecode` transform (3 tests)

**Tests**: 932210-1, 932210-3, 932210-4

**Rule 932210** (PL2, SQLite system command execution):

```
SecRule ARGS "@rx ;[\s\x0b]*\.[\s\x0b]*...shell|system..."
    "t:none,t:escapeSeqDecode,t:compressWhitespace,..."
```

Test payloads send `\n` as a literal two-character escape (e.g. `/get?foo=;\n.shell%20nc...`).
`escapeSeqDecode` converts `\n` → newline (0x0A), which is matched by `\s` in the regex's
`[\s\x0b]*` gap between `;` and `.shell`.  Without the transform the literal `\n` (backslash +
`n`) is not whitespace, so the regex does not match.

`parse_transform` in `parser.rs` has no `"escapesecode"` arm; the transform is silently
dropped.

**Fix** (`crates/waf-engine/src/rules/crs/`):
1. Add `CrsTransform::EscapeSeqDecode` variant in `types.rs`.
2. Map `"escapeseqdecode"` → `CrsTransform::EscapeSeqDecode` in `parse_transform`.
3. Implement in `transform.rs`: convert `\n`→`\n`, `\r`→`\r`, `\t`→`\t`, `\xHH`→byte,
   `\uHHHH`→UTF-8 char — matching ModSecurity's `escapeSeqDecode` semantics.

---

### Group 5 — `multiMatch` not supported (2 tests)

**Tests**: 934101-4, 934101-5

**Rule 934101** (PL2, Node.js injection):

```
SecRule ARGS "@rx (?:fork|spawn|require|...)[\s\x0b]*\("
    "t:none,t:urlDecodeUni,t:jsDecode,t:base64Decode,t:urlDecodeUni,t:jsDecode,
     multiMatch,..."
```

`multiMatch` tells ModSecurity to apply the operator *before and after each transform step*
and trigger if **any** step matches.  Without it, only the final (fully-transformed) value is
checked.  When `t:base64Decode` runs on a non-base64 string like
`require("child_process")...`, it produces garbage — the subsequent `urlDecodeUni/jsDecode`
passes don't recover the original text, so the regex fails on the terminal value.

With `multiMatch` the regex would match at the first (`urlDecodeUni`) stage, before
`base64Decode` corrupts the input.

**Fix**: implement `multiMatch` in the CRS rule evaluator (`crates/waf-engine/src/rules/crs/`).
When the `multiMatch` flag is set, run the operator after every transform step (not just the
last), and treat the rule as matching if any step returns true.

---

### Group 6 — Anomaly score below blocking threshold (1 test)

**Test**: 920201-1

**Rule 920201** (PL2):

```
SecRule REQUEST_BASENAME "@endsWith .pdf" "chain, severity:WARNING"
  SecRule REQUEST_HEADERS:Range "@rx ^bytes=...{63}" "setvar:inbound_anomaly_score_pl2+3"
```

The rule fires (chain head and member both match), adding `warning_anomaly_score` (3) to
`inbound_anomaly_score_pl2`.  With the default threshold of 5 a single warning is not enough
to block.  No PL1 rule fires alongside it for this specific request, so the total score stays
at 3 < 5.

In a real full-CRS deployment the score is cumulative across the entire request; the test
expects that **only** rule 920201 contributes, and that it is blocked.  The CRS test suite
assumes a threshold ≤ 3, or that the test backend is configured to block on any rule match
("anomaly mode with threshold=1").

**Options**:
- Lower `inbound_anomaly_score_threshold` from 5 to 3 in `tx.rs` (tighter, more aggressive).
- Accept this as a known false-negative at threshold=5 (document only).

---

### Group 7 — Further investigation required (4 tests)

These tests involve PL1/PL2 rules where both the PL gate and known transform/target issues
are not the sole cause.  A live debug session with the WAF running is needed.

| Test | Rule | PL | Note |
|------|------|----|------|
| 932371-1 | 932371 | 2 | `t:none`; regex `at`-command detection; possible regex compilation or pct_decode `+`→space issue |
| 941160-1 | 941160 | 1 | XSS with `xmlns=`; uses all transforms (all implemented); regex may not match after jsDecode/cssDecode chain |
| 941240-2 | 941240 | 1 | IE XSS `<importimplementation=`; similar to 941160 |
| 942500-1 | 942500 | 1 | MySQL `/*!...*/`; `multiMatch` present; regex should match but fails |
| 942500-2 | 942500 | 1 | Same rule, space before `!` variant |
| 943100-1 | 943100 | 1 | Session fixation `.cookie...domain=`; regex should match decoded query param |

Common candidates to check:
- URL query strings containing `{`, `"`, or `<` that may confuse the ARGS extractor.
- `+` character in query strings: our `url_decode_uni` decodes `%XX` but may not decode
  `+` → space; this alters whether whitespace-sensitive regexes match.
- `multiMatch` (see Group 5): 942500 uses `multiMatch`; without it the transforms chain may
  produce a different value.

---

## Fix priority

| Priority | Root cause | Tests fixed | Effort |
|----------|-----------|-------------|--------|
| 1 | `is_valid_utf8_encoded` (Group 2) | 4 | Low — one-liner |
| 2 | `t:escapeSeqDecode` (Group 4) | 3 | Low — new transform |
| 3 | `&ARGS` count target (Group 3) | 1 | Medium |
| 4 | `multiMatch` (Group 5) | 2+ | Medium |
| 5 | Debug Group 7 | up to 6 | Medium |
| 6 | PL3 / PL4 (Group 1) | 9–11 | Trivial (bump int) but raises FP risk |
| 7 | Threshold (Group 6) | 1 | Trivial but affects all rules |
