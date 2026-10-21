---
name: cookies
description: >
  Judge the cookies a site sets: whether each one is protected from script,
  from being sent over plaintext, and from being attached to cross-site
  requests. Covers Secure, HttpOnly and SameSite, plus scope and lifetime.
  Not response headers, not TLS, not CORS.
allowed-tools:
  - get_cookies
---

# Skill: Cookie flags

How to judge the cookies a site sets. The format is the SDK's; the security
method below is the part a security engineer owns and should correct.

## Scope

The `Set-Cookie` headers on one response, and what each cookie's attributes
let a browser do with it. Nothing about what the cookie contains — the probe
never returns a value, only its length, and that is deliberate.

Out of scope: whether the site needs that cookie at all, and anything that
requires logging in.

## Tool

| Tool | When |
|---|---|
| `get_cookies` | Once, at the start. Everything below is read out of its result. |

An empty `cookies` list is a real answer: this response set no cookies.
Report that in `notes` and return no findings. It is not a failure, and it
is not a clean bill of health for cookies set elsewhere on the site.

## Method

Each entry in `cookies` has these fields.

| Field | What it is |
|---|---|
| `name` | the cookie name |
| `value_length` | how long the value is. **The value itself is never returned** |
| `secure` | sent only over https |
| `httponly` | unreadable from JavaScript |
| `samesite` | `Strict`, `Lax`, `None`, or `null` when the attribute is absent |
| `domain` | `null` means host-only; a leading dot means all subdomains |
| `path` | where the cookie is sent |
| `expires` | `null` means a session cookie, gone when the browser closes |

Also read `final_url` and `redirects`: cookies set on a redirect belong to
the response that set them, and `status` tells you which page you are
judging.

For each cookie, in this order:

1. **`secure`.** Absent on an https response is a finding — the cookie will
   be sent in clear text if anything ever downgrades the connection.
2. **`httponly`.** Absent means any script on the page can read it. For a
   session cookie that is how an XSS becomes an account takeover.
3. **`samesite`.** Absent, or `None` without `secure`, is a finding. See the
   table below.
4. **Scope.** A leading dot in `domain` widens the cookie to every
   subdomain, including ones other teams control. `path: /` is normal; a
   narrower path on a sensitive cookie is better.
5. **Lifetime.** A session cookie that persists for years is worth a line.
   Read `expires`.

### What the name tells you

Judge severity by what the cookie plainly is. These names mean a session or
an identity, and a missing flag on one of them is far worse than on an
analytics cookie:

`session`, `sess`, `sid`, `auth`, `token`, `jwt`, `login`, `logged_in`,
`remember`, `csrf`, `xsrf`

A cookie whose name says analytics — `_ga`, `_gid`, `utm_*` — carries no
authority. A missing `HttpOnly` on it is `low` at most.

### SameSite

| Value | Meaning |
|---|---|
| `Strict` | never sent cross-site. Safest, and breaks inbound links |
| `Lax` | the modern browser default. Fine for most cookies |
| `None` | sent cross-site. **Requires `secure`** or browsers reject the cookie outright |
| absent | browsers default to `Lax`, but say nothing and you inherit whatever the next browser version decides |

## Not findings

| Seen | Why it is not a finding |
|---|---|
| `httponly: false` on an analytics cookie | It is meant to be read by script. That is the point of it. |
| `samesite: null` | Browsers default to `Lax`. Worth `info` for being unstated, not a vulnerability. |
| A long `value_length` | Length is not strength and not weakness. It is reported so you never have to look at the value. |
| `secure` missing on an `http://` response | On plaintext the flag cannot help. Report the missing https instead, and that belongs to another check. |
| A session cookie with no `expires` | Expiring when the browser closes is the safer choice, not a defect. |

## Must cover

`Secure` · `HttpOnly` · `SameSite`

Address all three for the cookies that matter, even when the answer is that
they are set correctly.

## Severity

Rank by what the cookie protects.

| | |
|---|---|
| **high** | a session or auth cookie missing `HttpOnly`, or missing `Secure` on https |
| **medium** | a session cookie with no `SameSite`, or `SameSite=None` without `Secure` |
| **low** | a non-authority cookie missing a flag; a cookie widened to all subdomains |
| **info** | lifetime notes, unstated attributes with a safe browser default |

## Reporting rules

- `location` is the cookie name, exactly as the tool spelled it.
- **Never quote, guess at, or reconstruct a cookie value.** The probe
  returns only `value_length` precisely so that a value cannot reach a
  report by accident. `value_length: 352` is evidence; the value is not.
- One finding per cookie per problem. Three cookies missing `HttpOnly` is
  three findings, not one that lists them.
- A tool failure is an error, never a finding.
- Report, do not advise. Name the attribute that is missing and what its
  absence allows. Do not write the `Set-Cookie` line they should send: you
  do not know whether the cookie is read by a script that would break.
