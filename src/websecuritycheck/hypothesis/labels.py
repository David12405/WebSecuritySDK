"""Endpoint ids, said out loud.

Module 2 identifies an endpoint by a twelve-character hash of its origin,
path and method, which is the right thing to store: it is stable, it cannot
be spelled two ways, and it survives a path being re-rendered. It is the
wrong thing to show anyone. `6aca10a32fec` tells a reader nothing, and - more
importantly - it tells a *model* nothing either.

That second point is why this is not only cosmetics. Deciding whether
`keyword` reaches a SQL sink is much easier knowing the endpoint is
`POST /api/search` than knowing it is `4f3207dc5bf7`: the path carries the
same intent the parameter name does, and the two corroborate each other.

A label is presentation and prompt material only. `Hypothesis.target_endpoint_id`
stays the hash - the schema requires it, and Module 3 resolves against it -
so nothing here ever reaches the data a later stage validates.

The labels come from `TargetModel.endpoints`, which lives in the Module 1
request rather than in the correlation envelope. With no request to hand,
`label_for` returns the hash and every caller keeps working.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ..domain.analysis_models import Module2AnalysisRequest
from ..domain.models import EndpointDefinition, TargetModel


def endpoint_labels(source: object) -> dict[str, str]:
    """Map each endpoint id to `"METHOD /path"`.

    Accepts whatever the caller happens to hold - a request, a target model,
    or just the endpoints - because the request is not always kept alongside
    the envelope and making the caller dig it out would be the only reason
    they would need to know the difference.
    """
    endpoints = _endpoints_of(source)
    labels: dict[str, str] = {}
    for endpoint in endpoints:
        labels[endpoint.endpoint_id] = f"{endpoint.method} {endpoint.path}"
    return labels


def label_for(endpoint_id: str | None, labels: Mapping[str, str] | None) -> str:
    """The readable name, or the id when there is nothing better to say."""
    if endpoint_id is None:
        return "(no endpoint)"
    if not labels:
        return endpoint_id
    return labels.get(endpoint_id, endpoint_id)


def describe(endpoint_id: str | None, labels: Mapping[str, str] | None) -> str:
    """`"POST /api/search (4f3207dc5bf7)"` - readable, still traceable.

    Both halves on purpose: a reader needs the path, and anyone comparing
    this against Module 2's own output or Module 3's results needs the id
    that appears there.
    """
    if endpoint_id is None:
        return "(no endpoint)"
    label = label_for(endpoint_id, labels)
    return endpoint_id if label == endpoint_id else f"{label} ({endpoint_id})"


def _endpoints_of(source: object) -> Iterable[EndpointDefinition]:
    if isinstance(source, Module2AnalysisRequest):
        return source.target_model.endpoints
    if isinstance(source, TargetModel):
        return source.endpoints
    if isinstance(source, Mapping):
        # A plain `{endpoint_id: "GET /path"}` is already the answer; callers
        # that built one by other means should not have to unbuild it.
        return []
    if isinstance(source, Iterable):
        return [item for item in source if isinstance(item, EndpointDefinition)]
    return []
