from __future__ import annotations

import httpx
import pytest
import respx

from tae import __version__
from tae.client import errors as e
from tae.client.http import HttpClient, normalize_base_url
from tests.conftest import BASE


def make(sleeps: list[float] | None = None, **kw: object) -> HttpClient:
    sink = sleeps if sleeps is not None else []
    return HttpClient(BASE, "ta_secret", sleep=sink.append, **kw)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://ta.test", "https://ta.test"),
        ("https://ta.test/", "https://ta.test"),
        ("https://ta.test/api", "https://ta.test"),
        ("https://ta.test/api/", "https://ta.test"),
        (" http://localhost:3001 ", "http://localhost:3001"),
        ("https://proxy.test/threatatlas", "https://proxy.test/threatatlas"),
    ],
)
def test_normalize_base_url(raw: str, expected: str) -> None:
    assert normalize_base_url(raw) == expected


def test_normalize_base_url_rejects_missing_scheme() -> None:
    with pytest.raises(ValueError, match="http"):
        normalize_base_url("ta.test")


def test_sends_bearer_token_and_user_agent(api: respx.MockRouter) -> None:
    route = api.get("/products").respond(json=[])
    make().get_json("/products")
    req = route.calls.last.request
    assert req.headers["Authorization"] == "Bearer ta_secret"
    assert req.headers["User-Agent"] == f"threatatlas-exporter/{__version__}"


def test_omits_auth_header_without_token(api: respx.MockRouter) -> None:
    route = api.get("/health").respond(json={})
    HttpClient(BASE, None).get_json("/health")
    assert "Authorization" not in route.calls.last.request.headers


def test_drops_none_params(api: respx.MockRouter) -> None:
    route = api.get("/diagrams").respond(json=[])
    make().get_json("/diagrams", {"product_id": None, "skip": 0})
    assert dict(route.calls.last.request.url.params) == {"skip": "0"}


def test_paginates_until_short_page(api: respx.MockRouter) -> None:
    pages = {0: [{"id": 1}, {"id": 2}], 2: [{"id": 3}, {"id": 4}], 4: [{"id": 5}]}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["limit"] == "2"
        assert request.url.params["product_id"] == "12"
        return httpx.Response(200, json=pages[int(request.url.params["skip"])])

    route = api.get("/diagrams").mock(side_effect=handler)
    items = list(make().paginate("/diagrams", {"product_id": 12}, page_size=2))
    assert [i["id"] for i in items] == [1, 2, 3, 4, 5]
    assert route.call_count == 3


def test_paginate_stops_on_exact_multiple_with_empty_page(api: respx.MockRouter) -> None:
    api.get("/frameworks", params={"skip": "0"}).respond(json=[{"id": 1}, {"id": 2}])
    api.get("/frameworks", params={"skip": "2"}).respond(json=[])
    assert len(list(make().paginate("/frameworks", page_size=2))) == 2


def test_paginate_rejects_non_list(api: respx.MockRouter) -> None:
    api.get("/products").respond(json={"detail": "oops"})
    with pytest.raises(e.ResponseFormatError):
        list(make().paginate("/products"))


def test_retries_get_on_503_with_backoff(api: respx.MockRouter) -> None:
    route = api.get("/products").mock(
        side_effect=[httpx.Response(503), httpx.Response(502), httpx.Response(200, json=[])]
    )
    sleeps: list[float] = []
    assert make(sleeps, backoff=0.5).get_json("/products") == []
    assert route.call_count == 3
    assert sleeps == [0.5, 1.0]


def test_gives_up_after_retries(api: respx.MockRouter) -> None:
    route = api.get("/products").respond(503, json={"detail": "maintenance"})
    with pytest.raises(e.ServerError, match="maintenance"):
        make(retries=2).get_json("/products")
    assert route.call_count == 3


def test_does_not_retry_post_on_gateway_error(api: respx.MockRouter) -> None:
    route = api.post("/products").respond(502)
    with pytest.raises(e.ServerError):
        make().post_json("/products", {"name": "x"})
    assert route.call_count == 1


def test_retries_post_on_429_honouring_retry_after(api: respx.MockRouter) -> None:
    route = api.post("/products").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "2"}), httpx.Response(201, json={"id": 1})]
    )
    sleeps: list[float] = []
    assert make(sleeps).post_json("/products", {"name": "x"}) == {"id": 1}
    assert route.call_count == 2
    assert sleeps == [2.0]


def test_retry_after_is_capped(api: respx.MockRouter) -> None:
    api.get("/products").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "3600"}), httpx.Response(200, json=[])]
    )
    sleeps: list[float] = []
    make(sleeps).get_json("/products")
    assert sleeps == [30.0]


def test_connect_error_is_retried_then_raised(api: respx.MockRouter) -> None:
    route = api.post("/products").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(e.ConnectionFailed, match="refused"):
        make(retries=1).post_json("/products", {})
    assert route.call_count == 2


def test_read_timeout_not_retried_for_post(api: respx.MockRouter) -> None:
    route = api.post("/products").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(e.ConnectionFailed):
        make().post_json("/products", {})
    assert route.call_count == 1


@pytest.mark.parametrize(
    ("status", "exc"),
    [
        (400, e.ValidationFailed),
        (401, e.AuthenticationError),
        (403, e.PermissionDenied),
        (404, e.NotFound),
        (409, e.ApiError),
        (422, e.ValidationFailed),
        (500, e.ServerError),
    ],
)
def test_error_mapping(api: respx.MockRouter, status: int, exc: type[e.ApiError]) -> None:
    api.get("/products/9").respond(status, json={"detail": "nope"})
    with pytest.raises(exc) as info:
        make(retries=0).get_json("/products/9")
    assert info.value.status_code == status
    assert "nope" in str(info.value)


def test_validation_error_detail_is_readable(api: respx.MockRouter) -> None:
    detail = [{"loc": ["body", "likelihood"], "msg": "Score must be between 1 and 5", "type": "value_error"}]
    api.post("/diagram-threats").respond(422, json={"detail": detail})
    with pytest.raises(e.ValidationFailed, match=r"likelihood: Score must be between 1 and 5"):
        make().post_json("/diagram-threats", {})


def test_redirect_is_reported_not_followed(api: respx.MockRouter) -> None:
    api.get("/products").respond(302, headers={"Location": "https://sso.test/login"})
    with pytest.raises(e.ConnectionFailed, match=r"sso\.test/login"):
        make().get_json("/products")


def test_html_instead_of_json_is_explained(api: respx.MockRouter) -> None:
    api.get("/products").respond(200, text="<html>SPA</html>", headers={"Content-Type": "text/html"})
    with pytest.raises(e.ResponseFormatError, match="text/html"):
        make().get_json("/products")


def test_delete_handles_204(api: respx.MockRouter) -> None:
    route = api.delete("/products/3").respond(204)
    make().delete("/products/3")
    assert route.called
