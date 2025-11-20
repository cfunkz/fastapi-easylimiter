# fastapi‑easylimiter

[![GitHub stars](https://img.shields.io/github/stars/cfunkz/fastapi-easylimiter?style=social)](https://github.com/cfunkz/fastapi-easylimiter/stargazers) 
[![GitHub forks](https://img.shields.io/github/forks/cfunkz/fastapi-easylimiter?style=social)](https://github.com/cfunkz/fastapi-easylimiter/network/members) 
[![GitHub issues](https://img.shields.io/github/issues/cfunkz/fastapi-easylimiter)](https://github.com/cfunkz/fastapi-easylimiter/issues) 
[![GitHub license](https://img.shields.io/github/license/cfunkz/fastapi-easylimiter)](https://github.com/cfunkz/fastapi-easylimiter/blob/main/LICENSE) 
[![PyPI](https://img.shields.io/pypi/v/fastapi-easylimiter)](https://pypi.org/project/fastapi-easylimiter/)

---

An **ASGI async rate-limiting middleware** for FastAPI with **Redis** or **in-memory caching**, designed to handle **auto-generated routes** (e.g., FastAPI-Users) without decorators, for simplicity and performance.

---

## Features

- **Async rate limiting**
- **Optional temporary IP bans**
  - Configurable threshold (default 10 violations)
  - Sliding 30-min offense window
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
  - Uses `'X-Forwarded-For'` only when the sender is trusted
  - Rejects spoofed XFF headers
  - Supports `'CF-Connecting-IP'` from Cloudflare, verified against CF CIDRs
  - Fallback to ASGI `scope["client"]` if no trusted headers exist
- **Zero dependencies beyond Redis client**
  - Starlette-style ASGI middleware
- **Custom responses**
  - `HTMLResponse` for browser clients
  - `JSONResponse` for API clients

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
backend = AsyncRedisBackend(redis_client)

# Or for single-instance/local development:
# backend = InMemoryBackend()

rules = {
    "/": {"limit": 600, "period": 60},          # GLOBAL: 600 req/min per IP
    "/api/": {"limit": 10, "period": 1},
    "/api/users": {"limit": 1, "period": 2},
}

app.add_middleware(
    RateLimiterMiddleware,
    rules=rules,
    backend=backend,
    trusted_proxies=[""],     # OPTIONAL: your proxy IPs
    cloudflare=False,         # OPTIONAL: enable CF-Connecting-IP
    enable_bans=True,         # OPTIONAL: enable temporary bans
    ban_threshold=15,         # Violations before ban
    ban_duration=300,         # Ban length in seconds
    offenses_ttl=900,         # Offense counting window
    ban_page="<p>Your IP has been temporarily banned due to excessive requests.</p>", # OPTIONAL custom HTML
)
```

> Example: `/api/users/me` matches `/api/users` and `/api`. If **any** rule is exceeded → `429` returned.

---

### Redis Lua Script (atomic)

```lua
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
```

### Redis Key Patterns

| Key Pattern              | Example                    | Purpose                          |
| ------------------------ | -------------------------- | -------------------------------- |
| `rl:{client_ip}:{prefix}` | `rl:203.0.113.5:/api`      | Rate-limit counter per IP+prefix |
| `ban:{client_ip}`         | `ban:203.0.113.5`          | Temporary ban                    |
| `offenses:{client_ip}`    | `offenses:203.0.113.5`     | Offense counter for ban tracking |

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
| `offenses_ttl`    | int                       | Offense counting window in seconds          |
| `ban_page`        | str                       | Custom HTML ban page                        |

---

## Screenshot

<img width="1919" height="873" alt="fastapi-easylimiter screenshot" src="https://github.com/user-attachments/assets/bcfc5a56-f123-4d20-bb88-3e300ac042f7" />
<img width="1919" height="869" alt="image" src="https://github.com/user-attachments/assets/0991a7fc-29ff-4d25-b897-13f74c33bcf5" />
<img width="561" height="173" alt="image" src="https://github.com/user-attachments/assets/a50868a0-0e7e-496e-a781-1a23a0b2581f" />

---

## Contributing

Contributions and forks are always welcome! Adapt, improve, or extend for your own needs.

---

## Support

[![Buy Me a Coffee](https://cdn.ko-fi.com/cdn/kofi3.png?v=3)](https://ko-fi.com/cfunkz81112)

---

*Parts of this code were generated/assisted by AI (Grok).*

