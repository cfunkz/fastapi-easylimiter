import asyncio
from time import time
from typing import Optional, Callable, Dict, List
import redis.asyncio as redis_async
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse

# ----------------------------
# Backend Interface
# ----------------------------
class RateLimitBackend:
    async def incr(self, key: str, expire: Optional[int] = None) -> int: ...
    async def expire(self, key: str, ttl: int): ...
    async def ttl(self, key: str) -> int: ...

# ----------------------------
# Redis Backend (fully atomic)
# ----------------------------
class AsyncRedisBackend(RateLimitBackend):
    INCR_SCRIPT = """
    local c = redis.call('INCR', KEYS[1])
    if c == 1 and tonumber(ARGV[1]) > 0 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    return c
    """
    VIOLATIONS_SCRIPT = """
    local v = redis.call('INCR', KEYS[1])
    if v == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    return v
    """
    def __init__(self, redis_client: redis_async.Redis):
        self.redis = redis_client
        self.incr_script = redis_client.register_script(self.INCR_SCRIPT)
        self.viol_script = redis_client.register_script(self.VIOLATIONS_SCRIPT)

    async def incr(self, key: str, expire: Optional[int] = None) -> int:
        return int(await self.incr_script(keys=[key], args=[expire or 0]))

    async def expire(self, key: str, ttl: int):
        await self.redis.expire(key, ttl)

    async def ttl(self, key: str) -> int:
        t = await self.redis.ttl(key)
        return t if t >= 0 else 0

# ----------------------------
# In-Memory Backend (dev only)
# ----------------------------
class InMemoryBackend(RateLimitBackend):
    def __init__(self, cleanup_interval: int = 60):
        self.store: Dict[str, tuple[int, float]] = {}
        self.locks: Dict[str, asyncio.Lock] = {}
        self.cleanup_interval = cleanup_interval
        asyncio.create_task(self._cleanup())

    async def _lock(self, key: str) -> asyncio.Lock:
        return self.locks.setdefault(key, asyncio.Lock())

    async def incr(self, key: str, expire: Optional[int] = None) -> int:
        now = time()
        async with await self._lock(key):
            val, ts = self.store.get(key, (0, 0.0))
            if ts and now >= ts:
                val, ts = 0, 0.0
            val += 1
            if expire:
                ts = now + expire
            self.store[key] = (val, ts)
            return val

    async def expire(self, key: str, ttl: int):
        now = time()
        async with await self._lock(key):
            val, _ = self.store.get(key, (0, 0.0))
            self.store[key] = (val, now + ttl)

    async def ttl(self, key: str) -> int:
        val = self.store.get(key)
        if not val:
            return 0
        _, ts = val
        return max(int(ts - time()), 0) if ts else 0

    async def _cleanup(self):
        while True:
            await asyncio.sleep(self.cleanup_interval)
            now = time()
            expired = [k for k, (_, t) in self.store.items() if t and t < now]
            for k in expired:
                self.store.pop(k, None)
                self.locks.pop(k, None)

# ----------------------------
# Rate Limiter Middleware
# ----------------------------
class RateLimiterMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        rules: Dict[str, Dict[str, int]],
        backend: RateLimitBackend,
        backoff_threshold: int = 3,
        max_backoff: int = 60,
        key_func: Callable[[Scope], str] = lambda s: s["client"][0] if s.get("client") else "anon",
    ):
        self.app = app
        self.backend = backend
        self.backoff_threshold = backoff_threshold
        self.max_backoff = max_backoff
        self.key_func = key_func
        self.rules: List[tuple[str, int, int]] = sorted(
            ((p, c["limit"], c["period"]) for p, c in rules.items()),
            key=lambda x: len(x[0]),
            reverse=True,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path, user = scope["path"], self.key_func(scope)
        tasks = []
        headers = {}
        retry_after = 0

        for prefix, limit, period in self.rules:
            if not path.startswith(prefix):
                continue
            key = f"rl:{user}:{prefix}"
            viol_key = f"{key}:v"
            count_task = asyncio.create_task(self.backend.incr(key, period))
            tasks.append((prefix, limit, period, key, viol_key, count_task))

        if not tasks:
            return await self.app(scope, receive, send)

        # Await all counts
        for prefix, limit, period, key, viol_key, count_task in tasks:
            count = await count_task
            remaining = max(limit - count, 0)
            headers.update({
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(await self.backend.ttl(key) or period),
            })
            if count <= limit:
                continue

            # Atomic violation count
            violations = await self.backend.incr(viol_key, period * 5)
            backoff = min(period * (2 ** max(0, violations - self.backoff_threshold)), self.max_backoff)
            await self.backend.expire(key, backoff)
            retry_after = max(retry_after, backoff)

        if retry_after:
            resp = JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded. Retry after {retry_after}s."},
                headers={**headers, "Retry-After": str(retry_after)},
            )
            return await resp(scope, receive, send)

        # Add headers to normal response
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                h = message.setdefault("headers", [])
                for k, v in headers.items():
                    h.append((k.encode(), v.encode()))
            await send(message)

        await self.app(scope, receive, send_with_headers)