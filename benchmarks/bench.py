"""Throughput / latency of the middleware itself (no HTTP server in the loop).

    python benchmarks/bench.py --redis redis://localhost:6379/15 -n 50000 -c 200

Scenarios use the README config (4 rules match /api/users/me):
  allowed  - every request passes (many distinct client IPs)
  limited  - one client far over its limit, bans disabled (every request is a 429)
  banned   - one banned client (served from the in-process ban cache)
"""

import argparse
import asyncio
import statistics
import time

import redis.asyncio as aioredis

from fastapi_easylimiter import RateLimitMiddleware

RULES = {
    "/*": (200, 60, "moving"),
    "/api/*": (10, 1, "moving"),
    "/api/auth/*": (3, 1, "fixed"),
    "/api/users/me": (1, 5, "fixed"),
}


async def app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def noop_send(message):
    pass


async def receive():
    return {"type": "http.request"}


async def run(mw, n, concurrency, ip_for):
    latencies = []
    queue = iter(range(n))

    async def worker():
        for i in queue:
            scope = {"type": "http", "path": "/api/users/me", "client": (ip_for(i), 1), "headers": []}
            t0 = time.perf_counter()
            await mw(scope, receive, noop_send)
            latencies.append(time.perf_counter() - t0)

    t0 = time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(concurrency)))
    elapsed = time.perf_counter() - t0
    latencies.sort()
    return n / elapsed, statistics.median(latencies) * 1e3, latencies[int(len(latencies) * 0.99)] * 1e3


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--redis", default="redis://localhost:6379/15")
    ap.add_argument("-n", type=int, default=50_000)
    ap.add_argument("-c", type=int, default=200)
    args = ap.parse_args()

    pool = aioredis.BlockingConnectionPool.from_url(args.redis, max_connections=args.c)
    r = aioredis.Redis(connection_pool=pool)
    await r.flushdb()

    scenarios = [
        ("allowed", dict(ban_offenses=0), lambda i: f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}"),
        ("limited", dict(ban_offenses=0), lambda i: "1.2.3.4"),
        ("banned", dict(ban_offenses=1, ban_length="1h"), lambda i: "6.6.6.6"),
    ]
    print(f"{'scenario':<10}{'req/s':>12}{'p50 ms':>10}{'p99 ms':>10}")
    for name, kw, ip_for in scenarios:
        mw = RateLimitMiddleware(app, redis=r, rules=RULES, **kw)
        await run(mw, 2_000, args.c, ip_for)  # warm up (loads script, triggers bans)
        rps, p50, p99 = await run(mw, args.n, args.c, ip_for)
        print(f"{name:<10}{rps:>12,.0f}{p50:>10.3f}{p99:>10.3f}")
        await r.flushdb()
    await r.aclose()


if __name__ == "__main__":
    asyncio.run(main())
