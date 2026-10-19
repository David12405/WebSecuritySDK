"""Settings - model, scope, limits, server list.

Deliberately free of any `strands` import: the model is carried as a
`"provider:model-id"` string and `engine/models.py` is the single place that
turns it into a provider object.

Scope is required at construction. There is no default and no "scan
anything" mode.

INIT: no implementation yet.
"""
