# fastapi‑easylimiter
  
[![GitHub stars](https://img.shields.io/github/stars/cfunkz/fastapi-easylimiter?style=social)](https://github.com/cfunkz/fastapi-easylimiter/stargazers) [![GitHub forks](https://img.shields.io/github/forks/cfunkz/fastapi-easylimiter?style=social)](https://github.com/cfunkz/fastapi-easylimiter/network/members) [![GitHub issues](https://img.shields.io/github/issues/cfunkz/fastapi-easylimiter)](https://github.com/cfunkz/fastapi-easylimiter/issues) [![GitHub license](https://img.shields.io/github/license/cfunkz/fastapi-easylimiter)](https://github.com/cfunkz/fastapi-easylimiter/blob/main/LICENSE) [![PyPI](https://img.shields.io/pypi/v/fastapi-easylimiter)](https://pypi.org/project/fastapi-easylimiter/)


An ASGI async rate-limiting middleware for FastAPI with Redis or in-memory caching. Designed to handle auto-generated routes (such as those provided by FastAPI-Users) without requiring decorators, purely for simplicity.


## Features
- Async rate limiting
- Cache
  - Redis
  - In-Memory (single worker dev)
- Path Based Rules
- Multi-rule prefix matching
  - Capable of global rate-limits and per-route
- Standard rate-limit headers
  - `X-RateLimit-Limit`
  - `X-RateLimit-Remaining`
  - `X-RateLimit-Reset`
  - Retry-After on `429` responses
  - Tracking for remaining time sent in headers
- Proxy Aware
  - Uses `'X-Forwarded-For'` only when the sender is trusted
  - Rejects spoofed XFF headers
  - Uses `'CF-Connecting-IP'` when trusted requests pass through Cloudflare
  - Falls back to ASGI scope["client"] if no trusted headers exist
- Zero Dependencies Beyond Redis Client
  - Starlette-style ASGI middleware

 
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
    "/api/": {"limit": 60, "period": 60},
    "/api/users": {"limit": 1, "period": 2},
}

app.add_middleware(
    RateLimiterMiddleware,
    rules=rules,
    backend=backend,
    trusted_proxies=["127.0.0.1"]
)
```

Rules are automatically sorted longest-first as seen in the code example.

A request to `/api/users/me` will match:

- /api/users
- /api

Both rules count independently.

If ANY rule is exceeded → request becomes 429.

**Uses Atomic LUA script:**

```lua
local count = redis.call('INCR', key)
if count == 1 then redis.call('EXPIRE', key, period) end
```

Keys follow the pattern - `rl:{client_ip}:{prefix}`, which is saved as `rl:203.0.113.5:/api`


| Parameter         | Type                      | Description                                 |
| ----------------- | ------------------------- | ------------------------------------------- |
| `app`             | ASGIApp                   | FastAPI/ASGI app                            |
| `rules`           | dict                      | `{ prefix: {"limit": int, "period": int} }` |
| `backend`         | Redis or InMemory backend | Rate-limit storage                          |
| `trusted_proxies` | list[str]                 | Proxies allowed to send real client IP      |


## Contributing
Contributions and forks are always welcome!
Feel free to adapt, improve, or extend this middleware for your own needs. This was purely made out of personal necessity.

## Support



[![Buy Me a Coffee](https://cdn.ko-fi.com/cdn/kofi3.png?v=3)](https://ko-fi.com/cfunkz81112)












