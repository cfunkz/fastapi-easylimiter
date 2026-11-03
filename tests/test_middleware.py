import asyncio
import json

import pytest

from fastapi_easylimiter import RateLimitMiddleware, parse_duration


async def ok_app(scope, receive, send):
    if scope["type"] == "websocket":
        await send({"type": "websocket.accept"})
        return
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"ok"})


def make(r, rules, **kw):
    kw.setdefault("ban_offenses", 0)
    return RateLimitMiddleware(ok_app, redis=r, rules=rules, **kw)


async def call(mw, path="/", ip="1.1.1.1", accept=b"application/json", kind="http"):
    """Run one request through the middleware; return (status, headers, body)."""
    sent = []

    async def receive():
        return {"type": "websocket.connect"} if kind == "websocket" else {"type": "http.request"}

    async def send(message):
        sent.append(message)

    scope = {"type": kind, "path": path, "client": (ip, 1234), "headers": [(b"accept", accept)]}
    await mw(scope, receive, send)
    first = sent[0]
    if kind == "websocket":
        return first["type"], first.get("code"), first.get("reason")
    headers = {k.decode(): v.decode() for k, v in first.get("headers", [])}
    body = b"".join(m.get("body", b"") for m in sent[1:])
    return first["status"], headers, body


async def statuses(mw, n, **kw):
    return [(await call(mw, **kw))[0] for _ in range(n)]


def test_parse_duration():
    assert parse_duration(5) == 5000
    assert parse_duration(0.5) == 500
    assert parse_duration("250ms") == 250
    assert parse_duration("30s") == 30000
    assert parse_duration("3m") == 180000
    assert parse_duration("1h") == 3600000
    assert parse_duration("2d") == 172800000
    for bad in ("1h30m", "abc", "", "-1s"):
        with pytest.raises(ValueError):
            parse_duration(bad)


@pytest.mark.parametrize(
    "rules",
    [
        {},
        {"api": (1, 1, "fixed")},
        {"/a*": (1, 1, "fixed")},
        {"/a/*/b": (1, 1, "fixed")},
        {"/a": (1, 1, "sliding")},
        {"/a": (0, 1, "fixed")},
        {"/a": (1, 0, "fixed")},
        {"/a": (1, 1)},
        {"/a": (1, 1, "fixed"), "/a/": (2, 1, "fixed")},
    ],
)
def test_invalid_config(r, rules):
    with pytest.raises(ValueError):
        make(r, rules)


async def test_fixed_window_limit_and_headers(r):
    mw = make(r, {"/api/*": (3, 60, "fixed")})
    for remaining in (2, 1, 0):
        status, headers, _ = await call(mw, "/api/x")
        assert status == 200
        assert headers["ratelimit-policy"] == '"/api/*";q=3;w=60'
        assert headers["ratelimit"] == f'"/api/*";r={remaining};t=60'
    status, headers, body = await call(mw, "/api/x")
    assert status == 429
    assert 59 <= int(headers["retry-after"]) <= 61
    assert headers["ratelimit"].startswith('"/api/*";r=0;t=')
    assert json.loads(body)["error"] == "rate_limit_exceeded"


async def test_fixed_window_resets(r):
    mw = make(r, {"/*": (2, 0.3, "fixed")})
    assert await statuses(mw, 3) == [200, 200, 429]
    await asyncio.sleep(0.35)
    assert await statuses(mw, 3) == [200, 200, 429]


async def test_moving_window_carries_previous_window(r):
    win = 1.0
    mw = make(r, {"/*": (10, win, "moving")})

    async def elapsed():
        sec, usec = await r.time()
        return (sec + usec / 1e6) % win

    await asyncio.sleep(win - await elapsed() + 0.02)  # start of a Redis-clock window
    assert await statuses(mw, 11) == [200] * 10 + [429]
    # Halfway into the next window ~half of the previous count still applies,
    # so roughly 5 requests (not a full 10) are allowed. A fixed window would allow 10.
    await asyncio.sleep(1.5 * win - await elapsed())
    allowed = (await statuses(mw, 10)).count(200)
    assert 3 <= allowed <= 6, allowed


async def test_moving_window_retry_after_is_honest(r):
    mw = make(r, {"/*": (2, 0.4, "moving")})
    assert await statuses(mw, 2) == [200, 200]
    status, _, _ = await call(mw)
    assert status == 429
    # Wait until the window has fully passed twice: everything decayed.
    await asyncio.sleep(0.85)
    assert await statuses(mw, 2) == [200, 200]


async def test_all_rules_must_pass_and_denials_consume_nothing(r):
    mw = make(r, {"/*": (5, 60, "fixed"), "/api/*": (2, 60, "moving")})
    assert await statuses(mw, 3, path="/api/a") == [200, 200, 429]
    # The denied /api request did not use up global quota: 5 - 2 = 3 left.
    status, headers, _ = await call(mw, "/home")
    assert status == 200 and headers["ratelimit"] == '"/*";r=2;t=60'
    assert await statuses(mw, 3, path="/home") == [200, 200, 429]


async def test_tightest_rule_is_reported(r):
    mw = make(r, {"/*": (100, 60, "fixed"), "/api/*": (10, 1, "moving"), "/api/me": (1, 5, "fixed")})
    status, headers, _ = await call(mw, "/api/me")
    assert status == 200
    assert headers["ratelimit-policy"] == '"/api/me";q=1;w=5, "/api/*";q=10;w=1, "/*";q=100;w=60'
    assert headers["ratelimit"] == '"/api/me";r=0;t=5'


async def test_path_matching(r):
    mw = make(r, {"/api/*": (1, 60, "fixed"), "/exact": (1, 60, "fixed")}, exempt=["/api/docs/*"])
    assert (await call(mw, "/api"))[0] == 200  # '/api/*' covers '/api' itself
    assert (await call(mw, "/api/deep/nested/"))[0] == 429  # same shared bucket
    assert await statuses(mw, 3, path="/api/docs/x") == [200] * 3  # exempt
    assert await statuses(mw, 2, path="/exact/") == [200, 429]  # trailing slash normalized
    status, headers, _ = await call(mw, "/exact/child")  # exact does not match children
    assert status == 200 and "ratelimit" not in headers
    assert (await call(mw, "/apix"))[0] == 200  # '/api/*' is a path prefix, not a string prefix


async def test_clients_are_isolated(r):
    mw = make(r, {"/*": (1, 60, "fixed")})
    assert await statuses(mw, 2, ip="1.1.1.1") == [200, 429]
    assert await statuses(mw, 2, ip="2.2.2.2") == [200, 429]


async def test_key_func(r):
    def key(scope):
        return None if scope["path"] == "/internal" else "everyone"

    mw = make(r, {"/*": (1, 60, "fixed")}, key_func=key)
    assert (await call(mw, ip="1.1.1.1"))[0] == 200
    assert (await call(mw, ip="2.2.2.2"))[0] == 429  # shared identifier
    assert await statuses(mw, 3, path="/internal") == [200] * 3  # None skips limiting


async def test_html_error_page(r):
    mw = make(r, {"/*": (1, 60, "fixed")})
    await call(mw)
    status, headers, body = await call(mw, accept=b"text/html,*/*")
    assert status == 429 and headers["content-type"].startswith("text/html")
    assert b"429 Too Many Requests" in body


async def test_ban_and_escalation(r):
    mw = make(r, {"/*": (1, 60, "fixed")}, ban_offenses=3, ban_length="300ms", ban_max_length="500ms")
    assert await statuses(mw, 4) == [200, 429, 429, 403]
    mw._bans.clear()  # look at Redis, not the local cache
    sec, usec = await r.time()
    until = int(await r.hget("rl:1.1.1.1", "|b"))
    assert 0 < until - (sec * 1000 + usec // 1000) <= 300
    status, headers, body = await call(mw)
    assert status == 403 and headers["retry-after"] == "1"
    assert json.loads(body)["error"] == "forbidden"

    await asyncio.sleep(0.35)
    assert await statuses(mw, 3) == [429, 429, 403]  # still over the limit, second ban
    _, _, _, ban_ms = await mw._eval("rl:1.1.1.1", mw._plan("/").argv)
    assert 300 < ban_ms <= 500  # doubled (600), then capped at 500
    assert int(await r.hget("rl:1.1.1.1", "|l")) == 2
    assert 3_600_000 < await r.pttl("rl:1.1.1.1") <= 3_600_500  # level remembered for ban_counter_ttl


async def test_banned_clients_skip_redis(r):
    mw = make(r, {"/*": (1, 60, "fixed")}, ban_offenses=1, ban_length="10s")
    assert await statuses(mw, 2) == [200, 403]
    calls = 0
    real = mw._eval

    async def counting(*args):
        nonlocal calls
        calls += 1
        return await real(*args)

    mw._eval = counting
    assert await statuses(mw, 50) == [403] * 50
    assert calls == 0
    assert (await call(mw, ip="9.9.9.9"))[0] == 200  # others unaffected


async def test_site_ban_blocks_everything(r):
    mw = make(r, {"/*": (100, 60, "fixed"), "/login": (1, 60, "fixed")}, ban_offenses=1, ban_length="10s")
    assert await statuses(mw, 2, path="/login") == [200, 403]
    assert (await call(mw, "/home"))[0] == 403


async def test_endpoint_ban_is_scoped(r):
    mw = make(
        r,
        {"/*": (100, 60, "fixed"), "/login": (1, 60, "fixed")},
        ban_offenses=1,
        ban_length="10s",
        site_ban=False,
    )
    assert await statuses(mw, 2, path="/login") == [200, 403]
    assert (await call(mw, "/home"))[0] == 200
    assert (await call(mw, "/login"))[0] == 403


async def test_atomic_under_concurrency(r):
    mw = make(r, {"/*": (1000, 60, "fixed"), "/api/*": (100, 60, "moving")})
    results = await asyncio.gather(*(call(mw, "/api/x") for _ in range(500)))
    assert sum(1 for s, _, _ in results if s == 200) == 100
    results = await asyncio.gather(*(call(mw, "/x") for _ in range(1500)))
    assert sum(1 for s, _, _ in results if s == 200) == 900


async def test_websocket(r):
    mw = make(r, {"/ws": (1, 60, "fixed")})
    assert (await call(mw, "/ws", kind="websocket"))[0] == "websocket.accept"
    kind, code, reason = await call(mw, "/ws", kind="websocket")
    assert kind == "websocket.close" and code == 1008 and "429" in reason


async def test_lifespan_passthrough(r):
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    mw = RateLimitMiddleware(app, redis=r, rules={"/*": (1, 1, "fixed")})
    await mw({"type": "lifespan"}, None, None)
    assert seen == ["lifespan"]


async def test_fail_open_and_closed():
    import redis.asyncio as aioredis
    from redis.asyncio.retry import Retry
    from redis.backoff import NoBackoff
    from redis.exceptions import ConnectionError

    dead = aioredis.Redis(port=1, socket_connect_timeout=0.2, retry=Retry(NoBackoff(), 0))
    assert (await call(make(dead, {"/*": (1, 1, "fixed")})))[0] == 200
    with pytest.raises(ConnectionError):
        await call(make(dead, {"/*": (1, 1, "fixed")}, fail_open=False))
    await dead.aclose()


async def test_fastapi_integration(r):
    fastapi = pytest.importorskip("fastapi")
    httpx = pytest.importorskip("httpx")

    app = fastapi.FastAPI()

    @app.get("/api/users/me")
    async def me():
        return {"me": True}

    app.add_middleware(
        RateLimitMiddleware,
        redis=r,
        rules={
            "/*": (200, 60, "moving"),
            "/api/*": (10, 1, "moving"),
            "/api/auth/*": (3, 1, "fixed"),
            "/api/users/me": (1, 5, "fixed"),
        },
        exempt=["/docs"],
        ban_offenses=15,
        ban_length="3m",
        ban_max_length="30m",
        ban_counter_ttl="1h",
        site_ban=True,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.get("/api/users/me")
        assert first.status_code == 200 and first.json() == {"me": True}
        assert first.headers["ratelimit"] == '"/api/users/me";r=0;t=5'
        assert (await client.get("/api/users/me")).status_code == 429
        assert (await client.get("/docs")).status_code == 200


@pytest.mark.parametrize("algo", ["fixed", "moving"])
async def test_retry_after_is_exact(r, algo):
    """The script's retry hint (ms) is neither too short nor much too long."""
    mw = make(r, {"/*": (3, 0.5, algo)})
    plan = mw._plan("/")
    for _ in range(3):
        assert (await mw._eval("rl:x", plan.argv))[0] == 0
    status, _, _, retry_ms = await mw._eval("rl:x", plan.argv)
    assert status == 1 and 0 < retry_ms <= 1000
    if retry_ms > 100:
        await asyncio.sleep((retry_ms - 60) / 1000)
        assert (await mw._eval("rl:x", plan.argv))[0] == 1
    await asyncio.sleep(0.07)
    assert (await mw._eval("rl:x", plan.argv))[0] == 0


async def test_one_small_key_per_client(r):
    mw = make(r, {"/*": (100, 0.2, "moving"), "/auth": (1, 60, "fixed")}, ban_offenses=5)
    await call(mw, "/auth")
    await call(mw, "/auth")
    await call(mw, "/")
    assert await r.keys("*") == [b"rl:1.1.1.1"]
    # TTL follows the longest window, so the /auth counter survives /-only traffic.
    assert 119_000 < await r.pttl("rl:1.1.1.1") <= 120_000


async def test_reloads_script_after_redis_flush(r):
    mw = make(r, {"/*": (5, 60, "fixed")})
    assert await statuses(mw, 2) == [200, 200]
    await r.script_flush()
    results = await asyncio.gather(*(call(mw) for _ in range(5)))  # one pipeline, all NOSCRIPT
    assert sorted(s for s, _, _ in results) == [200, 200, 200, 429, 429]


async def test_unusual_patterns_are_escaped(r):
    mw = make(r, {"/café/*": (1, 60, "fixed"), "/it's": (1, 60, "fixed")}, site_ban=False, ban_offenses=2)
    status, headers, _ = await call(mw, "/café/x")
    assert status == 200 and headers["ratelimit-policy"] == '"rule0";q=1;w=60'
    assert await statuses(mw, 3, path="/café/x") == [429, 403, 403]
    assert await statuses(mw, 2, path="/it's") == [200, 429]
