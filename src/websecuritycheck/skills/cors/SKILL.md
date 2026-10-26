---
name: cors
description: >
  Judge what a site is willing to share cross-origin: which origins it
  trusts, whether it sends credentials to them, whether it reflects back any
  origin it is handed, and whether a cache could serve one origin's response
  to another. Not response headers, not cookies, not TLS.
allowed-tools:
  - get_cors_policy
---

# Skill: CORS policy

How to judge what a site lets other origins read. The format is the SDK's;
the security method below is the part a security engineer owns and should
correct.

## Scope

The CORS answer to **one** request pair — a simple request and a preflight —
sent from an origin the site has no reason to trust. Nothing about what the
endpoint returns, and nothing about authentication.

CORS governs who may *read* a cross-origin response. It is not a firewall:
the request still reaches the server either way. A finding here is about
data a hostile page could read, never about a request it could make.

## Tool

| Tool | When |
|---|---|
| `get_cors_policy` | Once, at the start. Everything below is read out of its result. |

The probe sends `Origin: https://websecuritycheck.invalid`, an origin no
site should be configured to trust. That is the whole experiment: if it
comes back echoed, the site reflects whatever it is handed.

## Method

The result has these fields.

| Field | What it is |
|---|---|
| `origin_tested` | the origin the probe claimed to be |
| `allow_origin` | what came back in `Access-Control-Allow-Origin`; `null` when absent |
| `allow_credentials` | did the site say cookies may be sent |
| `origin_reflected` | **did `allow_origin` echo `origin_tested`** |
| `wildcard_origin` | was `allow_origin` exactly `*` |
| `vary_includes_origin` | does `Vary` list `Origin` |
| `simple`, `preflight` | status, headers and redirects of each exchange |

1. **No CORS at all.** `allow_origin: null` means cross-origin reads are
   blocked by the browser's default. That is the secure state. Say so in
   `notes` and move on — it is not a finding.
2. **Reflection.** `origin_reflected: true` is the serious one. The site
   trusts whoever asks, which is the same as trusting everyone, except it
   also passes the credentialed check that `*` would fail.
3. **Credentials.** Combine with step 2 and the table below.
4. **Caching.** If `allow_origin` varies by request but `Vary: Origin` is
   missing, a shared cache can hand one origin's response to another. The
   header is correct and the cache undoes it.
5. **Preflight.** Read `preflight.headers` for
   `Access-Control-Allow-Methods` and `-Headers`. Allowing `Authorization`
   or a write method widens what reflection is worth.

### The combinations that matter

| `allow_origin` | `allow_credentials` | Verdict |
|---|---|---|
| absent | — | Secure default. **Not a finding** |
| `*` | `false` | Public data, deliberately. Usually fine; note it |
| `*` | `true` | **Browsers refuse this combination outright.** The site is misconfigured and the rule does not work. Report as a configuration error, not as an exposure |
| reflected | `false` | Any site can read the response. Severity depends on what the endpoint returns |
| **reflected** | **`true`** | **The worst case.** Any page on the internet can read this endpoint *as the logged-in user*. This is a cross-site data-theft primitive |
| one fixed origin | either | Intended. Not a finding unless that origin is plainly wrong |

## Not findings

| Seen | Why it is not a finding |
|---|---|
| `allow_origin: null` | No CORS headers means no cross-origin reading. That is the default and it is safe. |
| `Access-Control-Allow-Origin: *` on a public asset | Fonts, images and public JSON are meant to be readable. Say so at `info` if at all. |
| A preflight that returns 404 or 405 | Many servers do not implement `OPTIONS`. Absence of a preflight answer is not a permission. |
| `allow_origin` naming a partner domain | A deliberate trust relationship. You cannot tell from here that it is wrong. |

## Must cover

`allow-origin` · `allow-credentials`

Address both, even when the answer is that the site sends neither.

**Name both in `notes`, in these words.** "No CORS headers were present" is
true and does not say which two you checked for.

## Severity

Rank by what a hostile page could actually read.

| | |
|---|---|
| **critical** | reflection plus credentials on an endpoint that returns user data |
| **high** | reflection plus credentials |
| **medium** | reflection without credentials on a non-public endpoint; `Vary: Origin` missing while the origin is reflected |
| **low** | wildcard on something that looks non-public |
| **info** | `*` with credentials disabled; a named third-party origin |

One probe tested one URL. If that URL returns nothing sensitive, say the
severity reflects this endpoint and that other paths were not tested.

## Reporting rules

- Quote the evidence from the tool result of **this** run — the
  `allow_origin` value as it came back, and `origin_tested` beside it so a
  reader can see what was sent.
- `location` is the URL that was probed.
- A tool failure is an error, never a finding.
- Never say the site "allows requests from anywhere". CORS does not stop
  requests. Say what can be **read**.
- Report, do not advise. Say which origins the policy reflects and what they
  can read. Do not propose an origin list: you cannot see which front-ends
  legitimately call this API, and a list that omits one breaks it.
