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

1. Read `security_headers_missing`. Each entry is a candidate finding.
2. Read `security_headers_present` and judge each value, not just its
   presence. A header that is set to something useless is worse than a
   missing one, because it looks handled.
3. Read `information_disclosure`. A version number is a finding; a bare
   product name usually is not.
4. Check `status` and `redirect_chain`. Headers on a 301 say nothing about
   the page the user lands on — if the chain ended elsewhere, say which
   response you judged.

### What "weak" means for the ones that have a value

| Header | Weak when |
|---|---|
| `strict-transport-security` | `max-age` under 15 552 000 (180 days), or absent from the value |
| `content-security-policy` | contains `unsafe-inline`, `unsafe-eval`, or `default-src *` |
| `x-frame-options` | anything other than `DENY` or `SAMEORIGIN` |
| `x-content-type-options` | anything other than `nosniff` |
| `referrer-policy` | `unsafe-url`, or absent while the site uses query parameters |

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
