"""LAYER 3 - the rules.

Two kinds, and the difference is the whole point of this layer:

  hooks     HARD rules. They block or rewrite. The model does not get a vote.
            `lifecycle`, `scope_guard`, `injection_guard`, `retry`.
  steering  SOFT rules. They read an answer the model was entitled to give,
            decide it is not good enough, say why, and let it try again.
            `steering`, `output_validator`.

In the turn diagram the blue boxes are hooks and the orange boxes are steering.

INIT: no implementation yet.
"""
