"""End to end: real uvicorn with several worker processes sharing one Redis."""

import asyncio
import os
import subprocess
import sys
import time
from collections import Counter

import pytest
from conftest import free_port

httpx = pytest.importorskip("httpx")
pytest.importorskip("uvicorn")
pytest.importorskip("fastapi")

WORKERS = 4


@pytest.fixture(params=[0, 5], ids=["no-bans", "bans"])
def server(request, redis_url):
    import redis

    redis.Redis.from_url(redis_url).flushdb()
    port = free_port()
    env = {**os.environ, "REDIS_URL": redis_url, "BAN_OFFENSES": str(request.param)}
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "tests.server_app:app",
            "--port",
            str(port),
            "--workers",
            str(WORKERS),
            "--proxy-headers",
            "--forwarded-allow-ips",
            "127.0.0.1",
            "--log-level",
            "warning",
        ],
        env=env,
        cwd=os.path.dirname(os.path.dirname(__file__)),
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20
    while True:
        try:
            if httpx.get(url + "/health", headers={"x-forwarded-for": "10.9.9.9"}).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        assert proc.poll() is None and time.time() < deadline, "uvicorn did not start"
        time.sleep(0.2)
    time.sleep(1)  # let every worker finish booting
    yield url, request.param
    proc.terminate()
    proc.wait(10)
    redis.Redis.from_url(redis_url).flushdb()


async def blast(url, path, ip, n):
    limits = httpx.Limits(max_connections=100)
    async with httpx.AsyncClient(base_url=url, limits=limits, timeout=30) as client:
        responses = await asyncio.gather(*(client.get(path, headers={"x-forwarded-for": ip}) for _ in range(n)))
    return responses


async def test_exact_limit_across_workers(server):
    url, bans = server
    responses = await blast(url, "/limited", "203.0.113.1", 400)
    codes = Counter(r.status_code for r in responses)
    assert codes[200] == 50, codes  # exactly the limit, even with 4 processes racing
    assert codes[200] + codes[429] + codes[403] == 400
    assert (codes[403] > 0) == (bans > 0)
    assert len({r.json()["pid"] for r in responses if r.status_code == 200}) > 1  # really several processes
    ok = next(r for r in responses if r.status_code == 200)
    assert ok.headers["ratelimit-policy"] == '"/limited";q=50;w=60, "/*";q=1000;w=60'
    denied = next(r for r in responses if r.status_code != 200)
    assert int(denied.headers["retry-after"]) >= 1


async def test_sliding_limit_across_workers(server, redis_url):
    """Exactly `limit` requests pass when the burst stays inside one window.

    A burst that straddles a window boundary may let one or two extra requests through: the
    sliding window counter weights the previous window by its remaining overlap, which assumes
    those requests were spread evenly (the algorithm's documented approximation). The model
    test covers that case exactly, so here we start the burst well clear of a boundary.
    """
    import redis

    url, _ = server
    window, margin = 60.0, 20.0
    sec, usec = redis.Redis.from_url(redis_url).time()
    elapsed = (sec + usec / 1e6) % window
    if elapsed > window - margin:
        await asyncio.sleep(window - elapsed + 0.1)

    start = time.monotonic()
    codes = Counter(r.status_code for r in await blast(url, "/sliding", "203.0.113.2", 300))
    assert time.monotonic() - start < margin, "burst too slow to stay inside one window"
    assert codes[200] == 30, codes


async def test_clients_are_told_apart_through_the_proxy(server):
    url, _ = server
    results = await asyncio.gather(*(blast(url, "/limited", f"198.51.100.{i}", 60) for i in range(5)))
    for responses in results:
        assert Counter(r.status_code for r in responses)[200] == 50


async def test_ban_is_shared_by_all_workers(server):
    url, bans = server
    if not bans:
        pytest.skip("bans disabled")
    await blast(url, "/limited", "192.0.2.7", 120)  # 50 ok, 5 offenses, then banned
    responses = await blast(url, "/anything", "192.0.2.7", 200)  # spread over all workers
    assert Counter(r.status_code for r in responses) == {403: 200}
    assert (await blast(url, "/anything", "192.0.2.8", 1))[0].status_code == 200
