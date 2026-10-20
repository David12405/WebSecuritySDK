# WebSecurityCheck SDK — Architecture

**Version** 0.1 · **Status** init — folder skeleton only, no implementation yet
**Owner** Duc Dang

This file is the map between the turn diagram and the code. Every module in
the tree below carries a docstring naming the step of the diagram it serves;
this is the view from above.

---

## 1. What the SDK is

A developer installs one package, calls one typed method on a target they own,
and gets back a structured result.

```python
from websecuritycheck import SecurityChecker

checker = SecurityChecker(model="...", scope=["https://myapp.com"])
result = checker.check_headers(target="https://myapp.com")

result.findings   # problems in the target
result.errors     # failures of the SDK, a tool, or the model
result.trace      # every step the agent took
```

The developer never writes a prompt and never imports `strands`.

**Non-goals for v0.1:** active exploitation, authenticated scanning, fuzzing,
scanning targets the developer does not own.

---

## 2. The turn: every turn passes the context manager, steering and hooks

Two colours in the diagram, two kinds of rule, and the difference is the whole
design:

| | Kind | What it does | Code |
|---|---|---|---|
| 🟦 blue | **hook** | hard rule — blocks or rewrites, the model gets no vote | `policy/lifecycle.py`, `scope_guard.py`, `injection_guard.py`, `retry.py` |
| 🟧 orange | **steering** | guidance — says why an answer is not good enough, then the agent retries | `policy/steering.py`, `output_validator.py` |

### The seven steps

| # | Step | Module |
|---|---|---|
| 1 | `check_headers(target)` — the public API validates params and scope | `checker.py` |
| 2 | Build the agent from the `Check` — prompt, skill, tool allowlist, schema, hooks, context manager | `engine/runner.py` + `checks/base.py` |
| 3 | **Start run · BeforeInvocation** — open the trace; the TargetStore pins the previous run's summary | `policy/lifecycle.py`, `telemetry/trace.py`, `memory/target_store.py` |
| 4 | **Context manager** — pinned working memory + last N messages + stubs of the older ones | `memory/context.py` |
| 5 | **Model call** — one Strands `Agent` turn | `engine/runner.py` |
| 6 | **Steering · after model** — is every required topic covered, is every finding backed by evidence? | `policy/steering.py` |
| 7 | **Finish run · AfterInvocation** — save findings, errors and the tool log; compute the diff; return `CheckResult` | `policy/lifecycle.py`, `memory/target_store.py` |

### The tool branch (right-hand column)

```
tool call?  yes
  ↓
Steering · before tool      skill not loaded, or the same call failed twice
                            → guide and retry
  ↓
Scope guard · BeforeToolCall   out of scope or not allowlisted
                               → cancel_tool, record ErrorInfo
  ↓
Tool runs
  ↓
AfterToolCall hooks         failure → ErrorInfo; retry transient;
                            wrap as untrusted data; trim size;
                            full output → context store
  ↓
back through the context manager, next turn
```

### The answer branch (left-hand column)

After step 6, the `Output OK?` diamond asks two questions — does it validate
against the schema, and does it pass steering. **No** means guide and
regenerate, up to N tries. **Yes** means step 7.

---

## 3. Layers and folders

One folder per layer, so the code mirrors the diagram.

```
WebSecuritySDK/
├── docs/
│   ├── ARCHITECTURE.md          this file
│   └── GIT_FLOW.md              branches, commits, reviews, releases
├── README.md                    install + quick start
├── pyproject.toml
├── .env.example                 which API key to set; .env is gitignored
├── config/
│   └── servers.yaml             which MCP servers to connect to (Layer 5 config)
├── src/websecuritycheck/
│   ├── __init__.py              exports SecurityChecker, CheckResult, Finding
│   ├── checker.py          L1   public API, typed check methods
│   ├── config.py                model, scope, limits, server list
│   ├── checks/             L2   one Check definition per check
│   │   ├── base.py              Check model + REGISTRY
│   │   └── headers.py  tls.py  cookies.py  cors.py
│   ├── engine/                  the agent runtime
│   │   ├── runner.py            builds and drives the Agent for one check
│   │   ├── models.py            "provider:model-id" -> a Strands model
│   │   └── prompts.py           the shared system prompt
│   ├── policy/             L3   the rules: hooks (hard) + steering (soft)
│   │   ├── lifecycle.py         steps 3 and 7: start run / finish run
│   │   ├── scope_guard.py       hard: cancel out-of-scope calls
│   │   ├── injection_guard.py   hard: tool output is untrusted data
│   │   ├── retry.py             hard: transient tool failures
│   │   ├── output_validator.py  soft: schema failure -> regenerate, max N
│   │   ├── steering.py          soft: did it follow the skill?
│   │   └── errors.py            ScopeViolation, ToolCallError, ...
│   ├── tools/              L5   MCP client, allowlist, failure handling
│   ├── memory/                  context manager + TargetStore (SQLite)
│   ├── results/                 CheckResult, Finding, ErrorInfo (public)
│   ├── telemetry/               spans + hook events -> result.trace
│   └── skills/                  SKILL.md folders, one per check
├── mcp_servers/websec_tools/  L6  constrained security tool server
│   ├── server.py                MCP tool definitions
│   ├── probes.py                HTTP, TLS and CORS probes
│   ├── errors.py                stable tool errors and safe redaction
│   ├── nmap.py                  host/service discovery
│   ├── zap.py                   Spider and passive analysis
│   ├── whatweb.py               technology fingerprinting
│   └── openapi.py               API specification parsing
├── examples/
│   ├── probe_target.py          direct L6 recon verification, no MCP or model
│   └── run_check.py             full agent run, needs model credentials
└── tests/
```

Only `checker.py` and `results/` are public. Everything else is internal.

**Terminology.** *Harness* means the whole scaffolding around the model —
Layers 2 to 5 together. Layer 3 alone is the **policy layer**: hard rules
enforced by Strands hooks, soft rules applied by steering.

---

## 4. Design rules

1. **Strands stays internal.** Only `engine/`, `policy/` and `tools/mcp.py`
   import `strands`. `config.py` carries the model as a `"provider:model-id"`
   string; `engine/models.py` is the one place that resolves it.
2. **The scope guard runs before every tool call.** No path lets a tool touch a
   target that is not in scope — including one the model invented or read out
   of a page.
3. **Tool output is untrusted data.** It is wrapped and labelled before the
   model sees it, and nothing in it can change the prompt, the skill or the
   allowlist.
4. **Findings and errors never mix.** A check with errors returns `partial` or
   `failed`, never `passed`.
5. **Every result is reproducible from its trace.**
6. **The model never sets `status`.** Its output is `CheckOutput` — findings and
   notes. The harness fills in status, errors, diff and trace, so the model
   cannot hide a failed tool by declaring the check passed.
7. **A run that called no tool is never `passed`.** It measured nothing, so an
   empty findings list is the absence of evidence, not evidence of absence.

---

## 5. Contracts frozen before any code

### 5.1 Tool input

Every security tool, ours or a partner's, takes its target in an argument named
**`target`**. That is the single rule the scope guard depends on: it reads
`tool_use.input["target"]` without knowing what the tool does. A tool that
calls it `url`, `host` or `site` cannot be scope-checked and is not
allowlisted. Optional extra arguments are fine if they have defaults.

### 5.2 Tool output

Always this envelope, as structured JSON, never raw prose:

```json
{
  "summary": "200 HTTP/1.1 on https://example.com/ — 12 headers, 9 security headers missing",
  "data":    { "...": "tool-specific, machine-readable" },
  "truncated": false
}
```

`summary` is what survives context compaction as a stub, so it must carry the
headline fact alone. `data` is what findings quote. `truncated` means a cap cut
something, and the agent must report that rather than conclude from a partial
result.

### 5.3 Tool errors

An MCP `isError` result whose text begins with a stable code.

| Code | Meaning | Retry? |
|---|---|---|
| `E_INVALID_TARGET` | not a URL, wrong scheme | no |
| `E_CONNECT` | DNS or TCP failure | yes |
| `E_TIMEOUT` | exceeded the tool timeout | yes |
| `E_TLS` | handshake failed | no |
| `E_REDIRECT_LOOP` | more than 5 redirects | no |
| `E_HTTP` | other transport-level HTTP error | yes |
| `E_INTERNAL` | bug in the tool | no |
| `E_INVALID_ARGUMENT` | constrained tool argument is invalid | no |
| `E_TOOL_UNAVAILABLE` | external executable or daemon is unavailable | yes |
| `E_TOOL_FAILED` | external tool exited unsuccessfully | yes |
| `E_PARSE` | deterministic tool output could not be parsed | no |
| `E_UNSUPPORTED_INPUT` | input format or feature is unsupported | no |
| `E_SERVER_UNAVAILABLE` | MCP server did not start (raised by the SDK) | yes |
| `E_TOOL_MISSING` | a check declares a tool no server provides (SDK) | no |

A non-2xx HTTP status is **not** an error — it is data, in `data.status`.

### 5.4 Behaviour

Baseline probes are passive and read-only: ordinary HTTP requests or a TLS
handshake. L6 recon extensions are constrained implementations of Nmap,
traditional ZAP Spider, ZAP Passive Scan, WhatWeb and an OpenAPI parser. They
do not perform active vulnerability scanning, fuzzing, exploitation or writes.

L6 validates target syntax, tool arguments, subprocess argv, timeouts and
output limits. Scope authorization, assessment policy, orchestration and
evidence persistence belong to Layer 5 or a layer above. L6 returns
tool-specific structured data; the upper layer maps it to evidence and
observation schemas when needed.

`examples/probe_target.py` is a direct Layer 6 manual-verification utility.
It calls the Python implementations directly and bypasses the L5
scope/authorization layer. It is intended only for direct testing against
targets the operator is authorized to assess. It is not an MCP tool and does
not add orchestration to `server.py`.

### 5.5 L6 tool catalog

The four baseline tools are frozen in v0.1. The six recon tools are additive
L6 extensions. Adding or changing a tool name, required argument, output data
schema or stable error code is a cross-layer contract change and must be
synchronized with the Layer 5 MCP client.

| Tool | Implementation | Semantic mapping |
|---|---|---|
| `get_response_headers` | HTTP | `HTTP_METADATA`, `SECURITY_CONTROL` |
| `get_cookies` | HTTP | `AUTHENTICATION`, `SECURITY_CONTROL` |
| `get_tls_info` | TLS | `SECURITY_CONTROL` |
| `get_cors_policy` | HTTP | `SECURITY_CONTROL` |
| `discover_hosts` | Nmap host discovery | `NETWORK_HOST` |
| `discover_services` | Nmap service profiles | `NETWORK_HOST`, `NETWORK_SERVICE` |
| `crawl_web` | ZAP traditional Spider | `ENDPOINT` |
| `passive_web_analysis` | ZAP Passive Scan | `SECURITY_SIGNAL` |
| `fingerprint_web` | WhatWeb | `TECHNOLOGY` |
| `parse_api_spec` | Internal OpenAPI parser | `ENDPOINT` |

### 5.6 Result schema

```python
class Finding(BaseModel):
    id: str              # stable across runs, so runs can be diffed
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    location: str        # URL, header name, cookie name ...
    evidence: str        # quoted from a tool result in THIS run
    remediation: str
    tool_refs: list[str] # trace step ids this finding rests on

class ErrorInfo(BaseModel):
    kind: Literal["scope", "tool", "model", "validation", "timeout", "injection"]
    message: str
    tool: str | None
    code: str | None     # E_TIMEOUT, ...

class CheckResult(BaseModel):
    check: str
    target: str
    status: Literal["passed", "issues_found", "failed", "partial"]
    findings: list[Finding]
    errors: list[ErrorInfo]
    diff: RunDiff | None     # new / fixed / unchanged since the last run
    trace: list[TraceStep]
```

| findings | errors | status |
|---|---|---|
| none | none | `passed` — only if at least one tool ran |
| some | none | `issues_found` |
| some | some | `partial` |
| none | some | `failed` |

---

## 6. Scope policy

Scope is required at construction. There is no default and no "scan anything"
mode.

```python
SecurityChecker(model="...", scope=["https://myapp.com"])   # ok
SecurityChecker(model="...")                                # ValueError
```

`in_scope(target, scope, allow_subdomains)` decides, and stays a pure function
so it is unit-testable and usable with no agent in the loop. Rules in order:

| # | Rule | Note |
|---|---|---|
| 1 | Scheme must be `http` or `https` | Decided here, not left to the tool |
| 2 | Host must match | Subdomains only when `allow_subdomains=True` |
| 3 | `https` → `http` downgrade is refused | **Before** the port rule — the two schemes have different default ports, so comparing ports first would make this rule unreachable |
| 4 | Ports must match when either side states one | Two scheme defaults are compatible, so `http://x` → `https://x` still passes |
| 5 | A scope path longer than `/` is a required prefix | Lets a scope be narrowed to `/api` |
| 6 | Empty scope matches nothing | No "scan anything" mode |

A blocked call is cancelled with `event.cancel_tool`; the model receives the
cancellation as the tool result and must report it.

**Exempt from the allowlist:** the tools Strands injects itself, including the
per-check structured-output tool. They take no `target`, so there is nothing to
scope-check — and all three hooks must agree on the exempt set, or "this check
called no tool" becomes unprovable.

**Legal line.** Only scan a target you own or have written permission to test.
Passive is not the same as authorised.

---

## 7. Check catalog (v0.1)

| Check | Method | Tool | Skill | Must cover |
|---|---|---|---|---|
| `headers` | `check_headers` | `get_response_headers` | `skills/headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| `cookies` | `check_cookies` | `get_cookies` | `skills/cookies` | Secure, HttpOnly, SameSite |
| `tls` | `check_tls` | `get_tls_info` | `skills/tls` | protocol version, chain validity, expiry |
| `cors` | `check_cors` | `get_cors_policy` | `skills/cors` | allow-origin, allow-credentials |

`check_all(target)` runs all four and merges the results.

**Adding a check must need nothing but** a `Check` definition in `checks/` and a
skill folder — no change to the engine, the policy layer or the public API.

The "must cover" column feeds deterministic steering. A topic carries its
aliases, because not every topic is a literal string a model writes:

```python
required_coverage = {
    "expiry": ["expires", "expiration", "not_after", "expires_in_days"],
    "secure": [],
}
```

Draw aliases from the tool's own field names first — those are fixed by the
contract in 5.2 — and only then from how a model phrases things.

---

## 8. Open questions

**Mentor**
- [ ] Is building on Strands acceptable, or must the harness be our own code?
- [ ] Which model providers must be supported — Bedrock only, or also Anthropic / OpenAI / local?
- [ ] Are GitHub repositories a target type? That changes the tools, the scope guard and the skills.

**Partner**
- [ ] stdio or HTTP per MCP server, and who starts them?
- [ ] Confirm 5.1–5.4, especially `target` as the argument name and the `E_*` codes.
- [ ] The first 3–5 tools.
- [ ] Who writes each `SKILL.md`: format ours, security method theirs.
- [ ] Docker test app with known issues (missing headers, weak cookie flags, open CORS).

**Both**
- [ ] Is the Generator → Validator agent pair in scope, or a stretch goal?
