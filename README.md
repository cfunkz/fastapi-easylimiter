<h1 align="center">fastapi‑easylimiter</h1>

<p align="center">
  <a href="https://github.com/cfunkz/fastapi-easylimiter/stargazers"><img src="https://img.shields.io/github/stars/cfunkz/fastapi-easylimiter?style=social" alt="GitHub stars"></a>
  <a href="https://github.com/cfunkz/fastapi-easylimiter/network/members"><img src="https://img.shields.io/github/forks/cfunkz/fastapi-easylimiter?style=social" alt="GitHub forks"></a>
  <a href="https://github.com/cfunkz/fastapi-easylimiter/issues"><img src="https://img.shields.io/github/issues/cfunkz/fastapi-easylimiter" alt="GitHub issues"></a>
  <a href="https://github.com/cfunkz/fastapi-easylimiter/blob/main/LICENSE"><img src="https://img.shields.io/github/license/cfunkz/fastapi-easylimiter" alt="GitHub license"></a>
  <a href="https://pypi.org/project/fastapi-easylimiter/"><img src="https://img.shields.io/pypi/v/fastapi-easylimiter" alt="PyPI"></a>
</p>

<p align="center">
  <a href="https://ko-fi.com/cfunkz81112"><img src="https://cdn.ko-fi.com/cdn/kofi3.png?v=3" alt="Buy Me a Coffee" height="36" /></a>
</p>

---

A tiny, fast, **atomic** Redis rate limiter for FastAPI (or any ASGI app). All rules live in one
`add_middleware` call: no decorators, so it also covers auto-generated routes (e.g. FastAPI-Users).

- **One Redis round trip per request**, whatever the number of matching rules. Concurrent requests are pipelined together automatically.
- **Atomic**: ban check, every matching rule, offense counting and ban escalation run in one Lua script. Quota is only consumed when *all* rules pass.
- **Correct algorithms**: fixed window, and a millisecond-precision sliding window counter for `"moving"`.
- **Escalating bans** (doubling up to a cap), site-wide or per rule. Banned clients are rejected from memory without touching Redis.
- **One small Redis hash per client** that expires on its own.
- Pure ASGI middleware, the only dependency is `redis`. IETF `RateLimit` / `RateLimit-Policy` and `Retry-After` headers, JSON or HTML errors, WebSocket support.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Rules](#rules)
  - [Algorithms](#algorithms)
- [Bans](#bans)
- [Parameters](#parameters)
- [Responses](#responses)
- [Production notes](#production-notes)
- [How it works](#how-it-works)
- [Benchmarks](#benchmarks)
- [Testing your app with fakeredis](#testing-your-app-with-fakeredis)
- [Tests](#tests)
- [Screenshot](#screenshot)
- [Contributing](#contributing)

## Installation

```bash
pip install fastapi-easylimiter
pip install "fastapi-easylimiter[fast]"   # + hiredis, faster Redis protocol parsing
```

Requires Redis 5+ (or Valkey).

## Usage

```python
from fastapi import FastAPI
import redis.asyncio as redis
from fastapi_easylimiter import RateLimitMiddleware

app = FastAPI()
redis_client = redis.Redis(
    connection_pool=redis.BlockingConnectionPool.from_url(
        "redis://localhost:6379/0", max_connections=50, timeout=1, socket_timeout=0.5
    )
)

app.add_middleware(
    RateLimitMiddleware,
    redis=redis_client,
    rules={
        "/*": (200, 60, "moving"),
        "/api/*": (10, 1, "moving"),
        "/api/auth/*": (3, 1, "fixed"),
        "/api/users/me": (1, 5, "fixed"),
    },
    exempt=["/docs", "/openapi.json"],
    ban_offenses=15,
    ban_length="3m",
    ban_max_length="30m",
    ban_counter_ttl="1h",
    site_ban=True,
)
```

`/api/auth/login` matches `/api/auth/*`, `/api/*` and `/*`. The request passes only if **all three**
allow it, and only then is it counted against all three. If any rule is exceeded the response is `429`;
if the client is banned it is `403`.

## Rules

`"pattern": (limit, window, algorithm)`. `window` is seconds (`1`, `0.5`) or a duration string (`"500ms"`, `"30s"`, `"5m"`, `"1h"`, `"1d"`).

| Pattern          | Matches                                                         |
| ---------------- | --------------------------------------------------------------- |
| `/api/users/me`  | exactly `/api/users/me` (trailing slash ignored), nothing below |
| `/api/*`         | `/api`, `/api/`, `/api/users/123`, ... as **one shared bucket**  |
| `/*`             | everything                                                      |

`/api/*` is a path prefix, so it does not match `/apix`. `exempt` takes the same patterns and is checked first.
Matching is precompiled into dictionaries and cached per path, so it costs a few dict lookups.

### Algorithms

| Name       | Algorithm                 | Behaviour                                                                                                                                                        |
| ---------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `"fixed"`  | Fixed window              | Up to `limit` requests, counted from the client's first request, then reset after `window`. Cheapest; allows a burst at each reset.                              |
| `"moving"` | Sliding window counter    | Counts the current window plus the previous window weighted by how much of it still overlaps the trailing `window` (ms precision). Smooth, no boundary bursts, O(1) memory. Use it by default. |

Rejected requests never consume quota, and `Retry-After` is the exact time until the next request would be allowed.

## Bans

Every rejected request (429) is an offense. After `ban_offenses` offenses (each within two windows of the
previous one) the client is banned for `ban_length`. Each new ban doubles the previous one, up to `ban_max_length`.
The escalation level is forgotten `ban_counter_ttl` after the last ban ends.

With the config above: 15 rejected requests → 3 min ban → next time 6 min → 12 → 24 → 30 → 30 ...

`site_ban=True` blocks the client on every limited path; `site_ban=False` only on the rule that was abused.
`ban_offenses=0` disables bans.

## Parameters

| Parameter         | Default  | Description                                                                 |
| ----------------- | -------- | --------------------------------------------------------------------------- |
| `redis`           | required | `redis.asyncio.Redis` client                                                |
| `rules`           | required | `{pattern: (limit, window, "fixed" \| "moving")}`                           |
| `exempt`          | `()`     | Patterns that are never limited                                             |
| `ban_offenses`    | `8`      | Rejected requests before a ban, `0` = no bans                              |
| `ban_length`      | `"5m"`   | First ban length                                                            |
| `ban_max_length`  | `"30m"`  | Ban length cap                                                              |
| `ban_counter_ttl` | `"1h"`   | How long the ban level is remembered after a ban ends                       |
| `site_ban`        | `True`   | Ban everywhere (`True`) or only on the abused rule (`False`)               |
| `key_func`        | client IP| `scope -> str \| None` identifier, e.g. API key or user id. `None` skips limiting |
| `fail_open`       | `True`   | If Redis is down, let requests through (and log). `False` raises instead   |
| `prefix`          | `"rl"`   | Redis key prefix                                                            |

## Responses

Allowed responses get the [IETF RateLimit headers](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/)
for the tightest rule:

```
RateLimit-Policy: "/api/users/me";q=1;w=5, "/api/*";q=10;w=1, "/*";q=200;w=60
RateLimit: "/api/users/me";r=0;t=5
```

`429` and `403` responses carry `Retry-After`. Browsers (`Accept: text/html`) get an HTML page, everything else gets
`{"error": "rate_limit_exceeded" | "forbidden", "retry_after": 12}`. WebSockets are closed with code `1008` before the handshake completes.

## Production notes

- **Behind a proxy / load balancer**, the client IP is `scope["client"]`. Run uvicorn with
  `--proxy-headers --forwarded-allow-ips=<your proxy ips>` so it is the real client IP, not the proxy's,
  or pass your own `key_func`.
- Use a `BlockingConnectionPool` and short `socket_timeout` (as in the example) so a slow Redis cannot pile up connections.
- Time comes from the Redis server (`TIME`), so any number of app servers agree on windows and bans.
- Each client is one key, `rl:<identifier>`, a small hash holding its counters, offenses and bans.
- **Redis Cluster** works: pass a `redis.asyncio.RedisCluster`. Each request touches a single key, so it never crosses shards.
- If Redis restarts or flushes its script cache, the script is reloaded automatically. While Redis is unreachable,
  requests pass (`fail_open=True`) and the error is logged at most once every 10 seconds. After a failure Redis is
  skipped for one second, so a hung Redis costs at most one `socket_timeout` instead of piling requests up behind it.

## How it works

At startup the rules are compiled into one Lua script (limits, windows and field names baked in). Per request:

1. Path → matching rules (cached), identifier → in-process ban cache check.
2. `EVALSHA` with the client key and matched rule numbers. Requests arriving in the same event loop tick share a pipeline.
3. The script runs `TIME`, `HMGET`, `HSET` (+ `PEXPIRE` when a new window starts): it checks bans, evaluates every rule,
   then either consumes quota from all of them or records the offense and escalates the ban.

## Benchmarks

`python benchmarks/bench.py --redis redis://localhost:6379/15`: the middleware itself with the config above
(`/api/users/me` matches 4 rules), 200 concurrent requests, one Python process, local Redis 7, hiredis installed.

| Scenario                           | 0.5.0       | 1.0.0          |
| ---------------------------------- | ----------- | -------------- |
| allowed (4 rules)                  | 3,700 req/s | 36,000 req/s   |
| limited (429)                      | 10,200 req/s| 40,000 req/s   |
| banned (403)                       | 10,400 req/s| 320,000 req/s  |

Redis CPU per request is ~7 µs with one matching rule and ~14 µs with four.

## Testing your app with fakeredis

No Redis server is needed in your own test suite: the limiter runs on [fakeredis](https://github.com/cunla/fakeredis-py).
Install it with Lua support, since the limiter is a Lua script:

```bash
pip install "fakeredis[lua]"
```

```python
import fakeredis
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi_easylimiter import RateLimitMiddleware

app = FastAPI()
app.add_middleware(RateLimitMiddleware, redis=fakeredis.FakeAsyncRedis(), rules={"/*": (2, 60, "fixed")})


@app.get("/")
def home():
    return {"ok": True}


def test_rate_limit():
    with TestClient(app) as client:
        assert [client.get("/").status_code for _ in range(3)] == [200, 200, 429]
```

- fakeredis lives in one Python process, so it suits tests only, not several workers or servers.
- Without the `[lua]` extra fakeredis rejects the script, and with the default `fail_open=True` every request
  is let through. Pass `fail_open=False` in tests to make that an error instead.

## Tests

```bash
pip install -e ".[dev]"
pytest            # needs redis-server installed (or set REDIS_URL for the basic suite)
```

55 tests, all but two against real Redis servers, run in CI on Python 3.9, 3.11 and 3.13:

- **Differential test**: 12,000 random requests (time jumping from 0 ms to 90 s, landing exactly on window and ban
  edges) compared response by response with a plain-Python model of the spec, under four ban configurations.
  Checked by mutation testing: each of 14 deliberate bugs planted in the Lua script (off-by-ones, flipped
  comparisons, wrong expiries) makes it fail.
- **Real server**: uvicorn with 4 worker processes behind `--proxy-headers`. 400 simultaneous requests let through exactly the limit,
  clients are told apart by `X-Forwarded-For`, and a ban applies on every worker.
- **Failure modes**: Redis killed and restarted mid-traffic, a Redis that accepts connections but never answers, client disconnects mid-request,
  10,000 concurrent requests, a 2-connection pool, the Redis clock jumping backwards, and a 3-node Redis Cluster.
- Behaviour: limits and headers, all-or-nothing across rules, path matching, exempt paths, ban escalation and cap,
  site vs. endpoint bans, WebSockets, HTML/JSON errors, config validation, FastAPI integration, fakeredis.

## Screenshot
<div align="center">
    <img style="max-width: 100%; height: auto;" alt="image" src="https://github.com/user-attachments/assets/4579f130-ac83-457b-8fd1-eda720ce8123" />
    <img style="max-width: 100%; height: auto; margin-top: 10px;" alt="image" src="https://github.com/user-attachments/assets/23752a35-5bff-4ed1-bd72-e90fe6c41e00" />
</div>

## Contributing
Contributions and forks are always welcome! Adapt, improve, or extend for your own needs.