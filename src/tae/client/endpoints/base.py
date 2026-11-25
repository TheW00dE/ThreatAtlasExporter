"""Shared plumbing for resource endpoint classes."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, TypeAdapter, ValidationError

from tae.client.errors import ResponseFormatError
from tae.client.http import HttpClient, Params
from tae.models.api import RequestModel

T = TypeVar("T", bound=BaseModel)


def parse(model: type[T], data: Any, context: str) -> T:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise ResponseFormatError(f"{context}: unexpected response shape: {exc}") from exc


def parse_list(model: type[T], data: Iterable[Any], context: str) -> list[T]:
    try:
        return TypeAdapter(list[model]).validate_python(list(data))  # type: ignore[valid-type]
    except ValidationError as exc:
        raise ResponseFormatError(f"{context}: unexpected response shape: {exc}") from exc


def body(data: RequestModel | dict[str, Any]) -> dict[str, Any]:
    return data.payload() if isinstance(data, RequestModel) else data


class Resource(Generic[T]):
    """CRUD on a ``/api/<path>`` collection whose responses parse into ``model``."""

    path: str
    model: type[T]
    paginated: bool = True

    def __init__(self, http: HttpClient) -> None:
        self.http = http

    def _list(self, params: Params | None = None, model: type[T] | None = None) -> list[T]:
        model = model or self.model
        if self.paginated:
            items: Iterable[Any] = self.http.paginate(self.path, params)
        else:
            items = self.http.get_json(self.path, params) or []
        return parse_list(model, items, f"GET {self.path}")

    def get(self, item_id: int) -> T:
        path = f"{self.path}/{item_id}"
        return parse(self.model, self.http.get_json(path), f"GET {path}")

    def create(self, data: RequestModel | dict[str, Any]) -> T:
        return parse(self.model, self.http.post_json(self.path, body(data)), f"POST {self.path}")

    def update(self, item_id: int, data: RequestModel | dict[str, Any]) -> T:
        path = f"{self.path}/{item_id}"
        return parse(self.model, self.http.put_json(path, body(data)), f"PUT {path}")

    def delete(self, item_id: int) -> None:
        self.http.delete(f"{self.path}/{item_id}")
