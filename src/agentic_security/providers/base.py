"""Bounded, schema-validated model provider contracts."""

from __future__ import annotations

from typing import Any, Protocol, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class ModelProvider(Protocol):
    def generate(self, prompt: str, *, model: str | None = None) -> str: ...

    def generate_structured(
        self, prompt: str, schema: type[T], *, model: str | None = None
    ) -> T: ...


class MockModelProvider:
    def __init__(self, responses: list[str | dict[str, Any]]) -> None:
        self.responses = list(responses)

    def generate(self, prompt: str, *, model: str | None = None) -> str:
        if not self.responses:
            raise RuntimeError("mock response queue exhausted")
        response = self.responses.pop(0)
        return response if isinstance(response, str) else str(response)

    def generate_structured(self, prompt: str, schema: type[T], *, model: str | None = None) -> T:
        if not self.responses:
            raise RuntimeError("mock response queue exhausted")
        return schema.model_validate(self.responses.pop(0))


class ValidatingProvider:
    """Retry malformed structured output only, with a strict bound."""

    def __init__(self, delegate: ModelProvider, max_retries: int = 1) -> None:
        self.delegate = delegate
        self.max_retries = max_retries

    def generate(self, prompt: str, *, model: str | None = None) -> str:
        return self.delegate.generate(prompt, model=model)

    def generate_structured(self, prompt: str, schema: type[T], *, model: str | None = None) -> T:
        error: ValidationError | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return self.delegate.generate_structured(prompt, schema, model=model)
            except ValidationError as exc:
                error = exc
                prompt = (
                    f"{prompt}\nPrevious output failed schema validation. "
                    f"Return only valid structured data. Attempt {attempt + 2}."
                )
        assert error is not None
        raise error
