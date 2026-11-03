"""The limiter runs on fakeredis (with Lua support), so apps can test it without a Redis server."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_easylimiter import RateLimitMiddleware

fakeredis = pytest.importorskip("fakeredis")
pytest.importorskip("lupa")  # fakeredis[lua]: without it EVALSHA is unknown and the limiter fails open


def make_app(**kw) -> FastAPI:
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, redis=fakeredis.FakeAsyncRedis(), fail_open=False, **kw)

    @app.get("/{path:path}")
    def anything():
        return {"ok": True}

    return app


def test_limits_and_headers():
    with TestClient(make_app(rules={"/*": (2, 60, "fixed")})) as client:
        responses = [client.get("/") for _ in range(3)]
    assert [r.status_code for r in responses] == [200, 200, 429]
    assert responses[0].headers["ratelimit"] == '"/*";r=1;t=60'
    assert int(responses[2].headers["retry-after"]) >= 1


def test_all_rules_must_pass_and_bans_apply():
    rules = {"/*": (5, 60, "fixed"), "/api/*": (2, 60, "fixed")}
    with TestClient(make_app(rules=rules, ban_offenses=2)) as client:
        assert [client.get("/api/x").status_code for _ in range(5)] == [200, 200, 429, 403, 403]
        assert client.get("/home").status_code == 403  # site-wide ban
