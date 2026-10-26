---
name: tls
description: >
  Judge the TLS a site answers on: whether the certificate chain is trusted,
  whether the certificate is for this host, how soon it expires, and whether
  the protocol and cipher are still acceptable. Not response headers, not
  cookies, not CORS.
allowed-tools:
  - get_tls_info
---

# Skill: TLS and certificate

How to judge the TLS a site presents. The format is the SDK's; the security
method below is the part a security engineer owns and should correct.

## Scope

One TLS handshake with the host, and the certificate it presented. Nothing
about what the site sends afterwards — a missing HSTS header is the
`headers` check, a cookie without `Secure` is `cookies`.

The tool requires an `https://` target. An `http://` one is not a weak TLS
configuration, it is the absence of TLS, and this check cannot say anything
about it.

## Tool

| Tool | When |
|---|---|
| `get_tls_info` | Once, at the start. Everything below is read out of its result. |

If it fails, say so and stop. `E_TLS` means the handshake did not complete —
report that the probe failed, not that the site is insecure. The two are
different statements and only one of them is evidence.

## Method

The result has these fields.

| Field | What it is |
|---|---|
| `chain_valid` | did the certificate verify against the system trust store |
| `issuer`, `subject` | who signed it, and who for |
| `not_before`, `not_after` | the validity window, as timestamps |
| `days_to_expiry` | days left; **negative means already expired** |
| `sans` | the hostnames this certificate is actually valid for |
| `protocol`, `cipher` | what the handshake settled on |
| `hostname`, `port` | what was probed |

1. **Trust first.** `chain_valid: false` outranks everything else below. A
   browser refuses the page; nothing further matters until it is fixed.
2. **Name match.** Is `hostname` in `sans`? A wildcard `*.example.com`
   covers `a.example.com` but not `example.com` itself, and not
   `a.b.example.com`. A certificate valid for the wrong name fails the same
   way an untrusted one does.
3. **Expiry.** Read `days_to_expiry`. Negative is already broken. Below 30
   is a finding — somebody has to act before it becomes an outage.
4. **Protocol.** See the table below.
5. **Issuer.** Worth one line of context, rarely a finding on its own. A
   self-signed certificate shows as `issuer == subject` and will also have
   `chain_valid: false`; report it as the trust failure, not twice.

### Protocol and cipher

| Seen | Verdict |
|---|---|
| `TLSv1.3` | current, no finding |
| `TLSv1.2` | acceptable. No finding unless the cipher is weak |
| `TLSv1.1`, `TLSv1` | **finding.** Deprecated and removed from browsers |
| `SSLv3` and below | **critical.** Broken, not merely old |
| cipher containing `RC4`, `3DES`, `NULL`, `EXPORT`, `MD5` | **finding** whatever the protocol |

The handshake reports **one** negotiated protocol — the best the probe and
the server agreed on. It does not tell you whether the server would also
accept something worse. Do not claim the site "only supports TLS 1.3"; say
what this handshake settled on.

### Expiry

Read `days_to_expiry` and apply **exactly this**:

| `days_to_expiry` | |
|---|---|
| less than 0 | **critical** finding — the site is already broken for every visitor |
| 0 to 14 | **high** finding — renewal is overdue or about to be |
| **15 or more** | **not a finding.** Report nothing. Do not mention it as a risk |

Fifteen is not a cautious number, it is a deliberate one. Most certificates
today are issued for 90 days and renew automatically, so a healthy site
spends most of its life somewhere between 15 and 89 days remaining. Grading
that as a problem puts a finding on every correctly-run site, and a report
whose findings are mostly noise teaches its reader to skim.

If `days_to_expiry` is 15 or more, the certificate is **fine**. Say so in
`notes` if you like. Do not write a finding, at any severity, with any
wording. "Expires soon" at 39 days is wrong.

## Not findings

| Seen | Why it is not a finding |
|---|---|
| A 90-day certificate | Let's Encrypt and most modern CAs issue 90-day certificates and renew automatically. Short validity is the current practice, not a weakness. |
| `TLSv1.2` with a modern cipher | Still acceptable. Recommending 1.3-only locks out older clients for no measured gain. |
| `sans` listing many hostnames | A shared certificate is an operational choice, not a vulnerability. |
| An issuer you do not recognise | `chain_valid: true` means the system trust store recognised it. That is the test, not familiarity. |

## Must cover

`protocol` · `chain_valid` · `expiry`

Address all three, even when the answer is that they are sound. A report
that silently omits one cannot be told apart from one that forgot to look.

Note that a model rarely writes the word "expiry" — it writes "expires in 39
days" or quotes `not_after`. That is fine; the topic is covered. What is not
fine is not mentioning the validity window at all.

**All three belong in `notes` on a clean run**, where there is no finding to
carry them: the protocol that was negotiated, that the chain verified, and
how long the certificate has left.

## Severity

Rank by what is exposed on **this** target.

| | |
|---|---|
| **critical** | expired, or a protocol that is broken rather than old |
| **high** | chain not trusted, name mismatch, expiry within two weeks |
| **medium** | deprecated protocol still negotiated, expiry within a month |
| **low** | weak cipher on an otherwise sound configuration |
| **info** | issuer notes, expiry inside three months |

## Reporting rules

- Quote the evidence from the tool result of **this** run.
- `location` is the host and port — `github.com:443` — not a header name.
- A handshake that failed is an error, never a finding.
- Say what this handshake negotiated, never what the server "supports".
- Report, do not advise. State what was negotiated and what it exposes. Do
  not say which protocol to disable or when to renew: one handshake does not
  tell you which clients still depend on the configuration you would change.
