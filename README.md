# WebSecurityCheck SDK

A typed SDK for agentic web-security checks, built on Strands Agents.

Install one package, call one typed method on a target you own, get back a
structured result — findings, errors, remediation, trace. You never write a
prompt and never import `strands`.

```python
from websecuritycheck import SecurityChecker

checker = SecurityChecker(model="gemini:gemini-3.8-flash", scope=["https://myapp.com"])
result = checker.check_headers(target="https://myapp.com")

result.status     # passed | issues_found | partial | failed
result.findings   # problems in the target
result.errors     # failures of the SDK, a tool, or the model
result.trace      # every step the agent took
```

> **Status: week 2 of 8.** The tool path and the policy layer work; the agent
> loop does not exist yet, so `SecurityChecker` above is still a stub. What
> runs today, with no model credentials:
>
> | | |
> |---|---|
> | Four passive probes, served over MCP | `mcp_servers/websec_tools/` |
> | Scope guard + tool allowlist, with the `BeforeToolCall` hook | `policy/scope_guard.py` |
> | Injection guard, with the `AfterToolCall` hook | `policy/injection_guard.py` |
> | Result schemas, status rules, JSON and SARIF export | `results/` |
> | Two runnable demos | `examples/` |
>
> `pytest` is 179 tests with no network and no model.

---

## Checks in v0.1

| Check | Method | Covers |
|---|---|---|
| `headers` | `check_headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| `cookies` | `check_cookies` | Secure, HttpOnly, SameSite |
| `tls` | `check_tls` | protocol version, chain validity, expiry |
| `cors` | `check_cors` | allow-origin, allow-credentials |

`check_all(target)` runs all four.

---

## Install

```bash
pip install -e ".[dev]"
cp .env.example .env     # only needed for a full agent run, later
```

The examples import the package, so the editable install is the one setup
step. Without it they fail with `ModuleNotFoundError: websecuritycheck`.

## Run

```bash
# probe a site through a real MCP subprocess — no model needed
python examples/probe_target.py https://example.com
python examples/probe_target.py https://example.com --scope https://other.test  # watch it block
python examples/probe_target.py https://example.com --json report.json

# watch the policy hooks decide, on hand-built events — no network either
python examples/inspect_hooks.py

# tests: no network, no model
pytest
```

`examples/run_check.py` — one full agent run — is not written yet.

---

## Scope is required

```python
SecurityChecker(model="...", scope=["https://myapp.com"])   # ok
SecurityChecker(model="...")                                # ValueError
```

There is no default and no "scan anything" mode. A tool call to a target
outside the scope is cancelled before it runs, and the block is reported in
`result.errors`.

**Only scan a target you own or have written permission to test.** Every probe
in this SDK is passive and read-only, but passive is not the same as
authorised.

---

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | the layers, the turn diagram, the frozen contracts, the open questions |
| [docs/GIT_FLOW.md](docs/GIT_FLOW.md) | branches, commits, reviews, releases |
