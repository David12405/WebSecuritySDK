"""LAYER 2 - the check catalog.

One module per check, each exporting a `Check` into `base.REGISTRY`. Adding a
check must need nothing but a `Check` definition here plus a skill folder -
no change to the engine, the policy layer or the public API.

INIT: no implementation yet.
"""
