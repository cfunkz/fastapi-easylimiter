# fastapi‑easylimiter

[![GitHub stars](https://img.shields.io/github/stars/cfunkz/fastapi-easylimiter?style=social)](https://github.com/cfunkz/fastapi-easylimiter/stargazers) 
[![GitHub forks](https://img.shields.io/github/forks/cfunkz/fastapi-easylimiter?style=social)](https://github.com/cfunkz/fastapi-easylimiter/network/members) 
[![GitHub issues](https://img.shields.io/github/issues/cfunkz/fastapi-easylimiter)](https://github.com/cfunkz/fastapi-easylimiter/issues) 
[![GitHub license](https://img.shields.io/github/license/cfunkz/fastapi-easylimiter)](https://github.com/cfunkz/fastapi-easylimiter/blob/main/LICENSE) 
[![PyPI](https://img.shields.io/pypi/v/fastapi-easylimiter)](https://pypi.org/project/fastapi-easylimiter/)

---

An **ASGI async rate-limiting middleware** for FastAPI with **Redis** or **in-memory caching**, designed to handle **auto-generated routes** (e.g., FastAPI-Users) without decorators, for simplicity and ease of use.

---

**Cloudflare CIDRs updated 21/11/2025**

## Features

- **Async rate limiting**
- **Optional temporary IP bans**
  - Configurable threshold (default 10 violations)
  - Sliding 15-min offense window
  - 5-min ban on repeat abuse
- **Cache Backends**
  - Redis (recommended for multi-instance deployments)
  - In-Memory (single worker dev)
- **Path-based rules**
  - Supports multi-rule prefix matching
  - Global and per-route limits
- **Standard rate-limit headers**
  - `X-RateLimit-Limit`
  - `X-RateLimit-Remaining`
  - `X-RateLimit-Reset`
  - `Retry-After` on `429` responses
- **Proxy Aware**
  - Uses `'X-Forwarded-For'` only when the sender is trusted, hardened logic
  - Rejects spoofed XFF headers
  - Supports `'CF-Connecting-IP'` from Cloudflare, verified against CF CIDRs, when enabled
    - Must be public not private IP range.
  - Fallback to ASGI `scope["client"]` if no trusted headers exist
- **Zero dependencies beyond Redis client**
  - Starlette-style ASGI middleware
- **Custom responses**
  - `HTMLResponse` for browser clients
  - `JSONResponse` for API clients
- CRLF-injection–safe header parsing
- Allows banning direct connections (no proxy/CF) for dev/testing
---

## Installation

```bash
pip install fastapi-easylimiter
```

---

## Usage

```python
from fastapi import FastAPI
from fastapi_easylimiter import AsyncRedisBackend, InMemoryBackend, RateLimiterMiddleware
import redis.asyncio as redis_async

app = FastAPI()

REDIS_URL = "redis://localhost:6379/0"

# Redis backend (recommended for multi-instance deployments)
redis_client = redis_async.from_url(REDIS_URL, decode_responses=True)
backend = AsyncRedisBackend(
  redis_client,            # Redis pool/client
  fail_open=False,         # Allow requests if Redis is down
  key_prefix="ratelimit:", # Redis key prefix
  eval_timeout=30          # Eval timeout
  )

# Or for single-instance/local development:
# backend = InMemoryBackend()

rules = {
    "/": {"limit": 50, "period": 5},            # GLOBAL: 50 req/5sec per IP
    "/api/": {"limit": 10, "period": 1},        # API: 10 req/sec per IP
    "/api/users": {"limit": 30, "period": 60},  # USER ROUTES: 30 req/60sec per IP
}

app.add_middleware(
    RateLimiterMiddleware,
    rules=rules,
    backend=backend,
    trusted_proxies=None,     # OPTIONAL: your proxy IPs (Only set if behind a proxy such as nginx)
    cloudflare=False,         # OPTIONAL: enable CF-Connecting-IP (Only set when behind cloudflare)
    enable_bans=True,         # OPTIONAL: enable temporary bans
    ban_threshold=10,         # Violations before ban
    ban_duration=300,         # Ban length in seconds
    offense_ttl=600,         # Offense counting window
    ban_page="<p>Your IP has been temporarily banned.</p>",        # OPTIONAL custom HTML ban page
    rate_page="<p>Too many requests. Please try again later.</p>", # OPTIONAL custom HTML rate-limit page
    ban_direct=True           # ONLY SET WHEN RUNNING BAREMETAL NO CF AND NO PROXY
)
```

> Example: `/api/users/me` matches `/api/users` and `/api`. If **any** rule is exceeded → `429` returned.

---

### Redis Lua Script

```lua
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local count = redis.call("INCR", key)
local ttl = redis.call("TTL", key)

if ttl == -1 then
    redis.call("EXPIRE", key, window)
    ttl = window
end

local reset = now + ttl
local exceeded = count > limit and 1 or 0

return {count, reset, exceeded}
```

### Redis Key Patterns

| Full Key Pattern                       | Example                          | Purpose                                  |
| -------------------------------------- | -------------------------------- | ---------------------------------------- |
| `{key_prefix}:rl:{client_ip}:{prefix}` | `ratelimit:rl:203.0.113.5:/api`  | Rate-limit counter per IP + route prefix |
| `{key_prefix}:ban:{client_ip}`         | `ratelimit:ban:203.0.113.5`      | Temporary ban flag                       |
| `{key_prefix}:offenses:{client_ip}`    | `ratelimit:offenses:203.0.113.5` | Offense counter used for ban tracking    |

---

### Middleware Parameters

| Parameter         | Type                      | Description                                 |
| ----------------- | ------------------------- | ------------------------------------------- |
| `app`             | ASGIApp                   | FastAPI/ASGI app                            |
| `rules`           | dict                      | `{ prefix: {"limit": int, "period": int} }` |
| `backend`         | Redis or InMemory backend | Rate-limit storage                          |
| `trusted_proxies` | list[str]                 | Proxies allowed to trust XFF headers        |
| `cloudflare`      | bool                      | Enable Cloudflare IP extraction             |
| `enable_bans`     | bool                      | Enable temporary IP bans                    |
| `ban_threshold`   | int                       | Violations before ban                       |
| `ban_duration`    | int                       | Ban length in seconds                       |
| `offense_ttl`     | int                       | Offense counting window in seconds          |
| `ban_page`        | str                       | Custom HTML ban page                        |
| `rate_page`       | str                       | Custom HTML rate-limit page                 |
| `ban_direct`      | bool                      | Bypass all checks and ban directly          |

---

## Screenshot

<img width="1070" height="571" alt="image" src="https://github.com/user-attachments/assets/4579f130-ac83-457b-8fd1-eda720ce8123" />
<img width="1128" height="582" alt="image" src="https://github.com/user-attachments/assets/23752a35-5bff-4ed1-bd72-e90fe6c41e00" />
<img width="542" height="155" alt="image" src="https://github.com/user-attachments/assets/83045e50-e9a6-481e-9b65-69fb4fef6dd8" />
<img width="546" height="165" alt="image" src="https://github.com/user-attachments/assets/82f28d1c-be71-480a-a23d-3291db6d9571" />

---

## Contributing

Contributions and forks are always welcome! Adapt, improve, or extend for your own needs.

---

## Support

[![Buy Me a Coffee](https://cdn.ko-fi.com/cdn/kofi3.png?v=3)](https://ko-fi.com/cfunkz81112)

---

*Parts of this code were generated/assisted by AI (Claude, Grok).*




