"""Soft rule - a schema failure means regenerate, max N.

The "Output OK?" diamond in the diagram, schema half. A malformed structured
output is sent back to the model with the validation error attached, rather
than raised at the developer.

INIT: no implementation yet.
"""
