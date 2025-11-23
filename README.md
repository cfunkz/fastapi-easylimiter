# fastapi‑easylimiter

[![GitHub stars](https://img.shields.io/github/stars/cfunkz/fastapi-easylimiter?style=social)](https://github.com/cfunkz/fastapi-easylimiter/stargazers) 
[![GitHub forks](https://img.shields.io/github/forks/cfunkz/fastapi-easylimiter?style=social)](https://github.com/cfunkz/fastapi-easylimiter/network/members) 
[![GitHub issues](https://img.shields.io/github/issues/cfunkz/fastapi-easylimiter)](https://github.com/cfunkz/fastapi-easylimiter/issues) 
[![GitHub license](https://img.shields.io/github/license/cfunkz/fastapi-easylimiter)](https://github.com/cfunkz/fastapi-easylimiter/blob/main/LICENSE) 
[![PyPI](https://img.shields.io/pypi/v/fastapi-easylimiter)](https://pypi.org/project/fastapi-easylimiter/)

---

An **ASGI async rate-limiting middleware** for FastAPI with **Redis**, designed to handle **auto-generated routes** (e.g., FastAPI-Users) without decorators, for simplicity and ease of use.

---

## Features

- Path based rules (`/api/*`, `/auth/*`, exact matches)
- Fixed & sliding window algorithms (Lua)
- `RateLimit`, `RateLimit-Policy`, `Retry-After` headers
- Bans with back-off per IP with configurable window
- BaseHTTPMiddleware for FastAPI/Starlette
- Async Redis support
- Easy to configure
- No decorators needed
- HTML/JSON error responses
---

## TODO

- In-memory option
- Additional strategies

## Installation

```bash
pip install fastapi-easylimiter
```

---

## Usage

```python
from fastapi import FastAPI
import redis.asyncio as redis
from middleware.rate import RateLimitMiddleware

app = FastAPI()

redis_client = redis.from_url("redis://localhost:6379/0")

app.add_middleware(
    RateLimitMiddleware,
    redis=redis,
    rules={
        "/*": (200, 60, "fixed"),           
        "/api/*": (5, 1000, "sliding"),
        "/api/auth/*": (3, 1, "sliding"),
        "/api/users/me": (2, 30, "fixed"),
    },
    exempt=[],
    enable_bans=True,
    ban_offenses=8,
    ban_window="10m",
    ban_length="5m",
    ban_max_length="1d",
    )
```

> Example: `/api/auth/login` matches `/api/auth` and `/api`. If **any** rule is exceeded → `429` returned. If banned → `403` returned.

---

### Redis Key Patterns

| Key Pattern                               | Example                                   | Type        | Used For                                      |
| ------------------------------------------| ----------------------------------------- | ----------- | --------------------------------------------- |
| `rl:Fixe:{hash}:{limit}:{window}`         | `rl:Fixe:a1b2c3d4e5f6a7b8:100:60`         | String      | Fixed-window counter                          |
| `rl:Slid:{hash}:{limit}:{window}`         | `rl:Slid:a1b2c3d4e5f6a7b8:60:60`          | ZSET        | Sliding window request log                    |
| `offense:{identifier}`                    | `offense:203.0.113.5`                     | ZSET        | Offense tracking for ban escalation           |
| `ban:{identifier}`                        | `ban:203.0.113.5`                         | String+TTL  | Active ban flag                               |

---

### Middleware Parameters

| Parameter        | Type                              | Required | Description                          |
| ---------------- | --------------------------------- | -------- | ------------------------------------ |
| `redis`          | `redis.asyncio.Redis`             | Yes      | Redis async client                   |
| `rules`          | `Dict[str, Tuple[int, int, str]]` | Yes      | Path → (limit, period, strategy)     |
| `exempt`         | `Optional[List[str]]`             | No       | Paths that bypass rate limits        |
| `enable_bans`    | `bool`                            | No       | Enable/disable ban system            |
| `ban_offenses`   | `int`                             | No       | Offenses before ban triggers         |
| `ban_window`     | `str`                             | No       | Time window for offense accumulation |
| `ban_length`     | `str`                             | No       | Initial ban length                   |
| `ban_max_length` | `str`                             | No       | Maximum exponential ban ceiling      |

---

## Screenshot

<img width="1070" height="571" alt="image" src="https://github.com/user-attachments/assets/4579f130-ac83-457b-8fd1-eda720ce8123" />
<img width="1128" height="582" alt="image" src="https://github.com/user-attachments/assets/23752a35-5bff-4ed1-bd72-e90fe6c41e00" />

---

## Contributing

Contributions and forks are always welcome! Adapt, improve, or extend for your own needs.


## Support

[![Buy Me a Coffee](https://cdn.ko-fi.com/cdn/kofi3.png?v=3)](https://ko-fi.com/cfunkz81112)

---
