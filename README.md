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

> **Status: init.** This repository currently holds the folder skeleton and the
> contracts. Every module carries a docstring naming its job and the step of
> the turn diagram it serves; none of them have an implementation yet. Nothing
> below runs.

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

## Install (once there is something to install)

```bash
pip install -e ".[dev]"
cp .env.example .env     # then fill in the key for your provider
```

## Run

```bash
# investigate a site through the MCP tools — no model needed
python examples/probe_target.py https://example.com

# one full agent run — needs model credentials
python examples/run_check.py https://example.com --check headers

# tests: no network, no model
pytest
```

## Module 2 source analysis

The MCP server exposes `inspect_source_tree`, `read_source_file`,
`search_source`, and `analyze_source`. The first three are bounded,
repository-confined source tools. `analyze_source` invokes an externally
installed Semgrep binary using trusted server-side configuration:

```bash
export WEBSEC_SEMGREP_PATH=semgrep
export WEBSEC_SEMGREP_RULESET=p/default
python -m mcp_servers.websec_tools.server
```

Install Semgrep separately; the Python package does not bundle or download it.
The ruleset and executable are not caller-controlled MCP arguments, and
Semgrep output is analyzer observation rather than a vulnerability verdict.

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
