"""The `Check` definition and the registry.  Feeds step 2 of the diagram.

A `Check` is the whole declarative description of one check, and it is what
step 2 builds an agent from:

    name               "headers"
    prompt_template    the task text for this check
    skill              which skills/<name>/SKILL.md to load into the prompt
    tools              the fixed tool allowlist the scope guard enforces
    output_model       the structured-output schema the model must fill
    required_coverage  dict[topic, aliases] - what steering insists on
    max_iterations     turn limit for the agent loop

INIT: no implementation yet.
"""
