---
name: surface
description: >
  Map the reachable surface of one origin: the endpoints it serves and the
  technologies those responses reveal, then report genuine exposures. A
  multi-step recon check - crawl, then probe what crawl found. Not a
  per-header audit, not TLS, not cookies, not a CORS verdict; those are the
  single-purpose checks.
allowed-tools:
  - fingerprint_web
  - crawl_web
  - probe_http
  - explore_browser
  - parse_api_spec
---

# Skill: Surface mapping

How to map what a site exposes, in steps, where each step is chosen from what
the last one returned. The format is the SDK's; the security method below is
the part a security engineer owns and should correct.

## Scope

One origin's reachable surface: the **endpoints** it serves and the
**technologies** behind them. The answer is mostly a map. A single-purpose
check answers one question about one response; this one discovers *what there
is to ask about*, and only reports the exposures that are plainly wrong.

Out of scope, because another check owns each: the full header policy of the
root (`headers`), the TLS handshake (`tls`), cookie flags (`cookies`), the
CORS verdict (`cors`). If you notice one in passing, a line in `notes` is
enough — do not duplicate another check's finding.

## This is recon: a map, not a verdict

The inventory is the answer. Which endpoints exist, what runs behind them —
that goes in `notes`, and a run whose map is complete and finds nothing wrong
is a good run, not an empty one. A finding is the exception: a specific
exposure you can quote. A recon step pushed to produce findings invents them,
so when in doubt, it is a note.

## The steps

Work in order, and let each result decide the next. You do not know step 2
until step 1 has run — that is the point of doing this with judgement rather
than a fixed script.

**Call a tool at most once for the same input, and never to fish.** A tool
that failed does not succeed on a second identical call: if `crawl_web`
returns `E_TOOL_UNAVAILABLE`, that is final for this run — do not call it
again, note it and move on. A tool call that fails is recorded as an error
either way, so a tool fired on the wrong input is not a free guess; it is a
mark against the run. Call a tool only when its precondition below is met.

| Step | Tool | When |
|---|---|---|
| 1 | `fingerprint_web` | First, on the origin. **Once.** Names the technologies running. |
| 2 | `crawl_web` | On the origin. **Once.** If it fails, do not retry it. |
| 3 | `probe_http` | On the endpoints from step 2 worth a closer look — one call per endpoint. |
| 4 | `explore_browser` | Only if the page is JavaScript and step 2 found little. Surfaces endpoints the script calls that a spider cannot see. |
| 5 | `parse_api_spec` | **Only on a URL that is actually an API spec** — see step 5. Never on a page, a script, a stylesheet or an image. |

1. **Fingerprint.** Call `fingerprint_web` on the target **once**. Read the
   technologies it names — a product, a server, a framework, a version. Two
   rules it is easy to break: read what was detected from each entry's `name`,
   never from page text (a `Title` of "Admin" is a string the site chose, not
   a component that exists); and do not call a version vulnerable or outdated
   — the tool gives you no CVE, and a disclosed version is the finding, not a
   guess about what it is patched against. If WhatWeb is unavailable
   (`E_TOOL_UNAVAILABLE`), note it and read technologies from the `Server` and
   `X-Powered-By` headers `probe_http` returns instead.
2. **Crawl.** Call `crawl_web` on the target **once**. Read `endpoints` —
   their URLs, methods, status and content types. If it comes back
   `E_TOOL_UNAVAILABLE`, ZAP is not running on this machine; say so in
   `notes`, **do not call it again**, and continue with `probe_http` on the
   target and any path you can reason about.
3. **Probe what matters.** Not every endpoint — the ones that look
   administrative (`/admin`, `/manage`), internal (`/debug`, `/actuator`,
   `/.git`, `/.env`), or that accept input. For each, `probe_http` tells you
   the status, the response headers, and whether it answered without a login.
   **Only probe targets inside your scope.** A crawl result on another host
   is noted, never probed — the scope guard will cancel it anyway.
4. **Browser, if needed.** If step 2 found a near-empty page and the response
   was an HTML shell with scripts, call `explore_browser` on the target. Its
   `network_events` name the endpoints the page fetches at runtime.
5. **Spec, only if you found one.** `parse_api_spec` reads an OpenAPI or
   Swagger document, nothing else. Call it **only** on a URL that is one: the
   path ends in `.json`/`.yaml` or contains `openapi`/`swagger`/`api-docs`,
   **and** step 1–3 saw it served as JSON. A `.js` script, a `.css`
   stylesheet, the HTML page, an image — none of these is a spec; parsing one
   returns `E_PARSE` and buys nothing but an error on the run. If you found no
   spec, skip this step entirely and say so in `notes`. The bundled
   JavaScript of a single-page app is not an API spec.

## What is a finding

Each needs a quote from a tool result of this run.

| Exposure | `rule` | What makes it a finding |
|---|---|---|
| An endpoint reachable with no auth that should need it | `exposed-endpoint` | `probe_http` returned 200 for `/admin`, `/.git/config`, `/.env`, a backup file, a debug console |
| A dangerous method allowed | `dangerous-method` | the response or `OPTIONS` lists `PUT`, `DELETE`, `TRACE` on an endpoint that should not take them |
| Software and version disclosed | `version-disclosure` | a `Server` or `X-Powered-By` header, or a `fingerprint_web` entry, carries a version string, e.g. `nginx/1.14.0`, `WordPress 5.2` |
| A component that should not be reachable | `exposed-component` | `fingerprint_web` named an admin, debug or development component by its plugin `name` — not from a page title — and `probe_http` confirmed it answers |
| An API spec served to the public | `exposed-spec` | `parse_api_spec` read a spec that anyone can fetch, revealing internal endpoints |

## Not findings

| Seen | Why it is in `notes`, not a finding |
|---|---|
| The endpoint list itself | That is the map. It is the answer, not a defect. |
| A technology with no version | Knowing the stack is recon. A bare `Server: nginx` discloses nothing actionable. |
| A 404, 401 or 403 | The endpoint is *not* reachable, or *is* protected. That is the secure state. |
| An endpoint that merely exists | Existing is not an exposure. Reachable-without-auth-when-it-should-not-be is. |

## Must cover

`endpoints` · `technologies`

Address both in `notes`, even when neither yields a finding: the endpoints
you mapped, and the technologies the responses revealed. A surface report
that names neither cannot be told from one that never ran.

## Reporting rules

- Quote the evidence from the tool result of **this** run — a status code, a
  header value, a method list, a spec path, as it came back.
- `location` is the endpoint or URL the finding is about, spelled as the tool
  spelled it.
- `rule` is the exposure kind from the table — `exposed-endpoint`,
  `dangerous-method`, `version-disclosure`, `exposed-spec`. It is the
  finding's identity across runs, so keep it identical even as you reword the
  title.
- `source_tool` is the tool the evidence came from.
- A tool failure is an error, never a finding. `E_TOOL_UNAVAILABLE` is a fact
  about this machine, not the target — say so in `notes`.
- Report, do not advise. Say what is reachable and what it exposes; do not say
  how to lock it down. You can see one surface, not the application behind it.
