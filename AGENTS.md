# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

---

## 5. Project-Specific Rules

### WAF use-case tracking

`README.md` contains a fenced block between `<!-- USE_CASES_START -->` and `<!-- USE_CASES_END -->` with two tables:

- **Implemented** — features the binary currently handles end-to-end.
- **Designed / stubbed** — modules that exist (with `todo!()`) but are not yet wired into `pipeline::run_inbound`.

**When you add, wire up, or remove a use case:**

1. If you implement a stubbed use case (i.e. replace a `todo!()` with real logic AND wire it into the pipeline), move its row from the "Designed / stubbed" table to the "Implemented" table and update the Trigger/Response columns.
2. If you add a completely new detection module or capability, add a new row to "Designed / stubbed" immediately.
3. If you remove a capability, remove its row.
4. Keep the `#` column sequential within each table.
5. Do **not** touch any text outside the `USE_CASES_START` / `USE_CASES_END` block unless explicitly asked.

### Testing

#### CRS accuracy tests (go-ftw)

Run the full OWASP CRS regression suite (319 tests, cloud mode) with:
```
make test-ftw-crs
```

When `make test-ftw-crs` reports a failure like `920201-1 FAILED`, look up the exact request with:
```
python3 tests/ftw/find_test.py 920201-1          # show source test (log-based)
python3 tests/ftw/find_test.py 920201-1 --cloud  # show transformed test (status-based)
python3 tests/ftw/find_test.py 920201            # show all tests for rule 920201
```

The script prints the HTTP method, URI, request body, headers, and expected output so you can reproduce the failure manually or trace it through the engine.

#### Integration tests

All integration tests **must** be written as methods in `tests/rest_client.py` and invoked via `client.run_all()`.

- Do **not** create separate test scripts, pytest files, or ad-hoc curl scripts.
- Every new test case = a new `test_*` method on `TestClient`, added to `run_all()`.
- Run the suite with:
  ```
  python tests/rest_client.py --proxy http://127.0.0.1:8111 --api http://127.0.0.1:8112
  ```
- Use `self.check(name, response, expected_status)` for assertions.
- Use `self._skip(name)` inside an `except httpx.ConnectError` guard so tests degrade gracefully when the WAF is not running.
