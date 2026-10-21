"""The `tls` check.

Needs an `https://` target. On an `http://` one the probe returns
`E_INVALID_TARGET` and the run comes back `failed` with that error, which is
the honest answer: the absence of TLS is not a weak TLS configuration, and
this check has nothing to measure.
"""

from __future__ import annotations

from .base import Check, register

TLS = register(
    Check(
        name="tls",
        task=(
            "Examine the TLS the target answers on and report what is wrong with it. "
            "Call get_tls_info exactly once, then answer from what it returned.\n\n"
            "Report a finding for a chain that does not verify, a certificate that is "
            "not valid for this host, and a protocol or cipher that is no longer "
            "acceptable. Expiry is a finding only under the threshold the skill "
            "states - a certificate with weeks left is a healthy certificate, not a "
            "warning. Say what this handshake "
            "negotiated - never what the server 'supports', which one handshake "
            "cannot tell you."
        ),
        tools=("get_tls_info",),
        required_coverage={
            # Topics here are concepts, not field names, which is why each
            # one carries aliases. No model writes the word "expiry" - it
            # writes "expires in 39 days" or quotes `not_after`. The tool's
            # own field names come first, because the contract fixes them.
            "protocol": ["tlsv1", "tls 1", "cipher", "handshake"],
            "chain_valid": ["chain", "trusted", "certificate is valid", "verification"],
            "expiry": ["expires", "expiration", "not_after", "days_to_expiry", "days left"],
        },
    )
)
