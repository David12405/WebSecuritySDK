"""`"provider:model-id"` -> a Strands model object.

The one translation point between `config.Settings` and Strands, and the
reason `config.py` can stay free of any agent-framework import. A developer
configures a string; exactly one function in the package knows what to do
with it.

    "openai:gpt-4o-mini"   -> OpenAIModel
    "bedrock:anthropic..." -> BedrockModel
    "anthropic.claude-..." -> BedrockModel, because a bare id is a Bedrock id
"""

from __future__ import annotations

import os

from strands.models import BedrockModel
from strands.models.model import Model
from strands.models.openai import OpenAIModel

#: Environment variable each provider reads when no key is passed in.
API_KEY_VARS = {"openai": "OPENAI_API_KEY"}


def split_model(model: str) -> tuple[str, str]:
    """`"openai:gpt-4o-mini"` -> `("openai", "gpt-4o-mini")`.

    A string with no known prefix keeps its colons and is treated as a
    Bedrock model id, which is how Strands reads a bare id - `bedrock` is
    the default rather than an error, so an AWS user configures nothing.
    """
    provider, _, model_id = model.partition(":")
    if model_id and provider in {"openai", "bedrock"}:
        return provider, model_id
    return "bedrock", model


def build_model(model: str, *, api_key: str | None = None, temperature: float = 0.0) -> Model:
    """Resolve the configured string into something `Agent(model=...)` takes."""
    provider, model_id = split_model(model)

    if provider == "openai":
        key = api_key or os.environ.get(API_KEY_VARS["openai"])
        if not key:
            raise ValueError(
                "no OpenAI API key: set OPENAI_API_KEY in the environment (a .env file "
                "is read by examples/run_check.py) or pass Settings(api_key=...)"
            )
        return OpenAIModel(
            client_args={"api_key": key},
            model_id=model_id,
            params={"temperature": temperature},
        )

    return BedrockModel(model_id=model_id, temperature=temperature)
