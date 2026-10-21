"""Shared fixtures.

House rule: the test suite runs with no network and no model. Anything that
needs either belongs in `examples/`, not here.

Currently empty of fixtures: the certificate builders that lived here went
out with the probes they supported. Those probes are the partner's now, and
are tested in `test_l6_probes.py`.
"""

from __future__ import annotations
