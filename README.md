# fastapi‑easylimiter
  
[![GitHub stars](https://img.shields.io/github/stars/cfunkz/fastapi-easylimiter?style=social)](https://github.com/cfunkz/fastapi-easylimiter/stargazers) [![GitHub forks](https://img.shields.io/github/forks/cfunkz/fastapi-easylimiter?style=social)](https://github.com/cfunkz/fastapi-easylimiter/network/members) [![GitHub issues](https://img.shields.io/github/issues/cfunkz/fastapi-easylimiter)](https://github.com/cfunkz/fastapi-easylimiter/issues) [![GitHub license](https://img.shields.io/github/license/cfunkz/fastapi-easylimiter)](https://github.com/cfunkz/fastapi-easylimiter/blob/main/LICENSE) [![PyPI](https://img.shields.io/pypi/v/fastapi-easylimiter)](https://pypi.org/project/fastapi-easylimiter/)


An ASGI async rate-limiting middleware for FastAPI with Redis or in-memory caching. Designed to handle auto-generated routes (such as those provided by FastAPI-Users) without requiring decorators, purely for simplicity.


## Features
- Async rate limiting
- Optional temporary IP bans
  - Configurable threshold (default 10 violations)
  - Sliding 30-min offense window
  - 5-min ban on repeat abuse
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
  - Uses `'CF-Connecting-IP'` and chekcks connection IP against CF CIDR list
  - Falls back to ASGI scope["client"] if no trusted headers exist
- Zero Dependencies Beyond Redis Client
  - Starlette-style ASGI middleware
- HTMLResponse for banned browser clients or JSONResponse for API clients
 
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
    trusted_proxies=[""],     # ← NEW: your proxy IPs here: OPTIONAL
    cloudflare=False,         # ← NEW: enables CF-Connecting-IP: OPTIONAL
    enable_bans=True,         # ← NEW: turn on/off banning: OPTIONAL
    ban_threshold=15,         # ← violations before ban
    ban_duration=300,         # ← ban length in seconds
    offenses_ttl=900,        # ← offense counting window
    ban_page="<p>Your IP has been temporarily banned due to excessive requests.</p>", # ← NEW: custom ban page: OPTIONAL
)
```

A request to `/api/users/me` will match:

- /api/users
- /api

If ANY rule is exceeded → request becomes 429.

**Uses Atomic LUA script:**

```lua
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
```

**Existing key patterns in Redis**

- `rl:{client_ip}:{prefix}`
  - Example: `rl:203.0.113.5:/api`
- `ban:{client_ip}`
  - Example: `ban:203.0.113.5`
- `offenses:{client_ip}`
  - Example: `offenses:203.0.113.5`


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


<img width="1919" height="873" alt="image" src="https://github.com/user-attachments/assets/bcfc5a56-f123-4d20-bb88-3e300ac042f7" />


## Contributing
Contributions and forks are always welcome! Feel free to adapt and improve for your own needs.

## Support

[![Buy Me a Coffee](https://cdn.ko-fi.com/cdn/kofi3.png?v=3)](https://ko-fi.com/cfunkz81112)

Parts of this code were generated/assisted by AI (Grok).


