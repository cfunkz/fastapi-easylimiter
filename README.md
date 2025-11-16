# fastapi-easylimiter

Simple async rate-limiting middleware for FastAPI with Redis or in-memory caching.


## Simple design
- Async rate limiting
- Redis or in-memory cache
- Easy rules per URL paths.
- Optional rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`)

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
    "/api/users": {"limit": 1, "period": 2},
    "/api/": {"limit": 60, "period": 60}, # GLOBAL ONES GO LAST
}

app.add_middleware(
    RateLimiterMiddleware,
    rules=rules,
    backend=backend,
    backoff_threshold=3,
    max_backoff=60
)
```

## Contributing
Contributions and forks are always welcome!
Feel free to adapt, improve, or extend this middleware for your own needs. This was purely made out of personal necessity.

## Support

[![Buy Me a Coffee](https://cdn.ko-fi.com/cdn/kofi3.png?v=3)](https://ko-fi.com/cfunkz81112)