# Skill: HTTP security headers

How to judge the response headers of a site. The format is the SDK's; the
security method below is the part a security engineer owns and should
correct.

## Scope

What a browser is told to do by this response. Nothing about the body, the
application behind it, or anything that needs a second request.

Out of scope here: cookie flags (`cookies`), certificate and protocol
(`tls`), cross-origin sharing (`cors`). A finding about those belongs to
that check, not this one.

## Tool

| Tool | When |
|---|---|
| `get_response_headers` | Once, at the start. Everything below is read out of its result. |

If it fails, say so and stop. Do not report headers as missing on a response
you never received — absence of evidence is not evidence of absence.

## Method

The result has these fields. Read them in this order.

| Field | What it is |
|---|---|
| `security_headers_missing` | names of the four tracked headers that are absent |
| `security_headers_present` | names of the ones that are set — **names only, no values** |
| `headers` | every response header, lowercased, name → value. The values live here |
| `redacted_headers` | names the tool deliberately blanked. Not findings |
| `status`, `redirects`, `final_url` | which response you are judging |

1. **Missing.** Each name in `security_headers_missing` is a candidate
   finding.
2. **Present but weak.** For each name in `security_headers_present`, look
   its value up in `headers` and judge the value, not the presence. A header
   set to something useless is worse than a missing one, because it looks
   handled.
3. **Disclosure.** Look in `headers` for `server`, `x-powered-by`,
   `x-aspnet-version`, `x-generator`, `via`. A version number is a finding;
   a bare product name usually is not.
4. **Which response.** If `redirects` is non-empty, the headers you have are
   from `final_url`, not from the URL that was asked for. Say so.

Anything whose value reads `<redacted>` was blanked by the tool on purpose
— `set-cookie` and auth headers. That is not a finding and not evidence; it
means cookies are a different check's job.

### What "weak" means for the four

| Header | Weak when |
|---|---|
| `strict-transport-security` | `max-age` under 15 552 000 (180 days), or absent from the value |
| `content-security-policy` | contains `unsafe-inline`, `unsafe-eval`, or `default-src *` |
| `x-frame-options` | anything other than `DENY` or `SAMEORIGIN` |
| `x-content-type-options` | anything other than `nosniff` |

The tool tracks these four and no others. A header outside the list — a
missing `referrer-policy`, say — can still be reported if you see it absent
from `headers`, but say that you checked it yourself rather than implying
the tool flagged it.

### Not findings

Advice that was right once and is now wrong is worse than no advice: a
developer who acts on it makes the site less safe while believing the
opposite.

| Seen | Why it is not a finding |
|---|---|
| `x-xss-protection: 0` | **Correct, and the recommended value.** The browser XSS auditor it disables was removed because it introduced vulnerabilities of its own. Telling anyone to set `1; mode=block` is telling them to turn a hole back on. |
| `x-xss-protection` absent | Also fine. Modern browsers ignore it. |
| `server: nginx` or `server: github.com` | A product name with no version is not disclosure worth a finding. A version — `nginx/1.18.0` — is. |
| `x-frame-options` absent while CSP sets `frame-ancestors` | CSP supersedes it. Report at most `info`. |

## Must cover

`strict-transport-security` · `content-security-policy` · `x-frame-options`
· `x-content-type-options`

These four are what the check is asked to answer for. Address each one, even
when the answer is that it is present and sound — a report that silently
omits a topic cannot be told apart from one that forgot to look.

## Severity

Rank by what is exposed on **this** target, not by a table.

| | |
|---|---|
| **high** | The site handles credentials or sessions and has no CSP, or no HSTS on an https site |
| **medium** | A header is present but weak enough to be bypassed |
| **low** | A defence-in-depth header is missing on a site with nothing to protect |
| **info** | Version disclosure, legacy headers, anything with no attack behind it |

A missing header on a static page with no forms is not a high. Say what an
attacker would gain, and if nothing, the severity is low.

## Reporting rules

- Quote the evidence from the tool result of **this** run. Never from
  memory of what sites like this usually do.
- `location` is the header name, exactly as the tool spelled it.
- A tool failure is an error, never a finding.
- If the result says `truncated: true`, say so rather than concluding from a
  partial list.
- Remediation is the header to send, with a value. "Add CSP" is not
  remediation; `Content-Security-Policy: default-src 'self'` is.
