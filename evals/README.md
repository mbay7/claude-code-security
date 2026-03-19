# Security Evals

Automated test suite proving detection effectiveness of each hook.
Run with: `python -m pytest evals/ -v`

---

## Coverage

| File | Hook Tested | Threat | OWASP |
|------|-------------|--------|-------|
| `test_injection.py` | `security-scan.py` | Prompt injection — 18 cases | LLM01:2025 |
| `test_secrets.py` | `security-scan.py` | Secret exposure — 12 cases | LLM02:2025 |
| `test_memory.py` | `memory-write-guard.py` | Memory poisoning (MINJA) — 11 cases | LLM04:2025 |
| `test_behavioral.py` | `tool-audit.py`, `security-scan.py` | Behavioral anomalies — 14 cases | LLM05:2025 |

**Total: 55 test cases**

---

## Running Evals

```bash
# Full suite
python -m pytest evals/ -v

# Single category
python -m pytest evals/test_injection.py -v

# With summary only
python -m pytest evals/ --tb=no -q
```

---

## Test Design Principles

1. **True positives first** — every attack variant we claim to catch has a passing test
2. **False positive coverage** — every detection category has at least one clean-content test
3. **Edge cases** — empty input, malformed JSON, non-target tool types all handled
4. **No mocking** — tests call real hook code via importlib or subprocess. If the hook breaks, the eval breaks.

---

## Adding Tests

Each test file corresponds to one OWASP threat category. To add a new detection pattern:

1. Add the regex to the appropriate hook (`security-scan.py`, `memory-write-guard.py`, etc.)
2. Add a test case to the corresponding eval file
3. Add a clean-content test to verify no false positive is introduced
4. Run `python -m pytest evals/ -v` to confirm all tests pass

Pattern contributions must include a source reference — CVE number, OWASP ID, or research paper link.
