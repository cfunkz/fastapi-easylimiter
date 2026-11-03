"""Failure modes: Redis restarts, hangs and outages, cancelled requests, huge bursts, Redis Cluster."""

import asyncio
import logging
import random
import shutil
import socket
import subprocess

import pytest
import redis.asyncio as aioredis
from conftest import free_port, spawn_redis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from test_middleware import call, make, statuses

from fastapi_easylimiter import RateLimitMiddleware


def fast_fail_client(port: int, **kw) -> aioredis.Redis:
    return aioredis.Redis(port=port, socket_connect_timeout=0.3, socket_timeout=0.3, retry=Retry(NoBackoff(), 0), **kw)


async def test_survives_redis_restart(caplog):
    port = free_port()
    proc = spawn_redis(port)
    client = fast_fail_client(port)
    mw = make(client, {"/*": (3, 60, "fixed")})
    try:
        assert await statuses(mw, 4) == [200, 200, 200, 429]

        proc.kill()
        proc.wait()
        with caplog.at_level(logging.ERROR, logger="fastapi_easylimiter"):
            assert await statuses(mw, 20) == [200] * 20  # fail open while Redis is gone
        assert len(caplog.records) == 1  # and the error is logged once, not 20 times

        proc = spawn_redis(port)  # comes back empty: no counters, no cached script
        await asyncio.sleep(1.1)  # the limiter retries Redis at most once a second while it is down
        assert await statuses(mw, 4) == [200, 200, 200, 429]
    finally:
        proc.kill()
        proc.wait()
        await client.aclose()


async def test_hanging_redis_fails_open_fast():
    # A server that accepts connections but never answers (overloaded Redis, dead network path).
    hole = socket.socket()
    hole.bind(("127.0.0.1", 0))
    hole.listen(100)
    client = fast_fail_client(hole.getsockname()[1])
    mw = make(client, {"/*": (1, 1, "fixed")})
    try:
        loop = asyncio.get_running_loop()
        start = loop.time()

        async def later(i):
            await asyncio.sleep(i * 0.01)  # steady traffic, not one burst: 100 requests over a second
            return await call(mw, ip=f"10.3.0.{i}")

        results = await asyncio.gather(*(later(i) for i in range(100)))
        assert [s for s, _, _ in results] == [200] * 100
        # Each Redis call waits out the 0.3s timeout, but requests never queue up behind each other.
        assert loop.time() - start < 2.5
        with pytest.raises(aioredis.RedisError):
            await call(make(client, {"/*": (1, 1, "fixed")}, fail_open=False))
    finally:
        await client.aclose()
        hole.close()


async def test_cancelled_requests_do_not_break_the_batch(r):
    mw = make(r, {"/*": (100, 60, "fixed")})
    tasks = [asyncio.ensure_future(call(mw)) for _ in range(100)]
    await asyncio.sleep(0)
    for task in tasks[::2]:  # clients disconnect while their Redis call is in flight
        task.cancel()
    done = await asyncio.gather(*tasks, return_exceptions=True)
    finished = [d for d in done if not isinstance(d, BaseException)]
    assert len(finished) == 50 and all(s == 200 for s, _, _ in finished)
    # A cancelled request may or may not have reached Redis (and been counted); nothing else changes.
    used = 100 - int((await call(mw))[1]["ratelimit"].split("r=")[1].split(";")[0]) - 1
    assert 50 <= used <= 100
    await asyncio.sleep(0)
    assert not mw._pending and not mw._tasks


async def test_ten_thousand_concurrent_requests(r):
    mw = make(r, {"/*": (1000, 60, "moving"), "/api/*": (250, 60, "fixed")})
    results = await asyncio.gather(*(call(mw, "/api/x", ip=f"10.0.0.{i % 4}") for i in range(10_000)))
    allowed = sum(1 for s, _, _ in results if s == 200)
    assert allowed == 4 * 250


def cluster_port() -> int:
    """A free port whose cluster bus port (port + 10000) is valid and free too."""
    while True:
        port = random.randrange(20000, 50000)
        try:
            for p in (port, port + 10000):
                with socket.socket() as s:
                    s.bind(("127.0.0.1", p))
            return port
        except OSError:
            continue


async def wait_until_converged(ports, timeout=30.0):
    """Wait until every node reports a healthy cluster and the same slot map.

    `redis-cli --cluster create` returns before gossip has reached every node. A client that
    starts while nodes still disagree gets MOVED replies, refreshes its topology and drops
    connections that other in-flight commands are still using.
    """
    nodes = [aioredis.Redis(port=p, decode_responses=True) for p in ports]
    try:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            infos = [
                dict(line.split(":", 1) for line in (await n.execute_command("CLUSTER", "INFO")).split()) for n in nodes
            ]
            slot_maps = [sorted(map(str, await n.execute_command("CLUSTER", "SLOTS"))) for n in nodes]
            healthy = all(i["cluster_state"] == "ok" and int(i["cluster_known_nodes"]) == len(ports) for i in infos)
            if healthy and all(m == slot_maps[0] for m in slot_maps):
                return
            assert asyncio.get_running_loop().time() < deadline, "cluster did not converge"
            await asyncio.sleep(0.1)
    finally:
        for n in nodes:
            await n.aclose()


@pytest.fixture
async def cluster():
    if not shutil.which("redis-cli"):
        pytest.skip("redis-cli is not installed")
    ports = [cluster_port() for _ in range(3)]
    procs = [spawn_redis(p, "--cluster-enabled", "yes", "--cluster-config-file", "nodes.conf") for p in ports]
    try:
        subprocess.run(
            ["redis-cli", "--cluster", "create", *(f"127.0.0.1:{p}" for p in ports), "--cluster-yes"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        await wait_until_converged(ports)
        client = aioredis.RedisCluster(host="127.0.0.1", port=ports[0])
        yield client
        await client.aclose()
    finally:
        for proc in procs:
            proc.kill()
            proc.wait()


async def test_redis_cluster(cluster):
    mw = RateLimitMiddleware(
        None, redis=cluster, rules={"/*": (5, 60, "fixed"), "/api/*": (3, 60, "moving")}, ban_offenses=2
    )
    plan = mw._plan("/api/x")
    # 30 clients spread over all three shards, 10 requests each, all at once.
    results = await asyncio.gather(*(mw._eval(f"rl:10.1.0.{i % 30}", plan.argv) for i in range(300)))
    codes = [status for status, *_ in results]
    assert codes.count(0) == 30 * 3
    assert codes.count(2) == 30 * 6  # second offense bans; the rest are rejected as banned
    await cluster.script_flush()  # a failover to a fresh node loses the script cache
    status, *_ = await mw._eval("rl:fresh-client", plan.argv)
    assert status == 0


async def test_tiny_connection_pool_is_enough(redis_url):
    """Pipelining means a burst needs a handful of connections, not one per request."""
    client = aioredis.from_url(redis_url, max_connections=2)
    try:
        mw = make(client, {"/*": (500, 60, "fixed")}, fail_open=False)
        results = await asyncio.gather(*(call(mw, ip=f"10.2.0.{i % 10}") for i in range(10_000)))
        assert sum(1 for s, _, _ in results if s == 200) == 10 * 500
    finally:
        await client.flushdb()
        await client.aclose()
