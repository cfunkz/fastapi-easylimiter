# fastapi_ultrafast_ratelimiter.py

import asyncio
from time import time
from typing import Optional, Callable, Dict
import redis.asyncio as redis_async
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse

# ----------------------------
# Backend Interface
# ----------------------------
class RateLimitBackend:
    async def incr(self, key: str, expire: Optional[int] = None) -> int:
        raise NotImplementedError

    async def expire(self, key: str, ttl: int):
        raise NotImplementedError

    async def ttl(self, key: str) -> int:
        raise NotImplementedError

# ----------------------------
# Redis Backend (atomic)
# ----------------------------
class AsyncRedisBackend(RateLimitBackend):
    LUA_SCRIPT = """
    local current = redis.call('INCR', KEYS[1])
    if current == 1 and tonumber(ARGV[1]) > 0 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    return current
    """
    def __init__(self, redis_client: redis_async.Redis):
        self.redis = redis_client
        self.incr_script = self.redis.register_script(self.LUA_SCRIPT)

    async def incr(self, key: str, expire: Optional[int] = None) -> int:
        return int(await self.incr_script(keys=[key], args=[expire or 0]))

    async def expire(self, key: str, ttl: int):
        await self.redis.expire(key, ttl)

    async def ttl(self, key: str) -> int:
        ttl = await self.redis.ttl(key)
        return ttl if ttl >= 0 else 0

# ----------------------------
# In-Memory Backend (single-worker)
# ----------------------------
class InMemoryBackend(RateLimitBackend):
    def __init__(self, cleanup_interval: int = 60):
        self.store: Dict[str, tuple[int, float]] = {}
        self.locks: Dict[str, asyncio.Lock] = {}
        self.cleanup_interval = cleanup_interval
        asyncio.create_task(self._cleanup())

    async def _get_lock(self, key: str) -> asyncio.Lock:
        if key not in self.locks:
            self.locks[key] = asyncio.Lock()
        return self.locks[key]

    async def incr(self, key: str, expire: Optional[int] = None) -> int:
        now = time()
        lock = await self._get_lock(key)
        async with lock:
            val, exp_ts = self.store.get(key, (0, 0))
            if exp_ts and now >= exp_ts:
                val, exp_ts = 0, 0
            val += 1
            if expire:
                exp_ts = now + expire
            self.store[key] = (val, exp_ts)
            return val

    async def expire(self, key: str, ttl: int):
        now = time()
        lock = await self._get_lock(key)
        async with lock:
            val, _ = self.store.get(key, (0, 0))
            self.store[key] = (val, now + ttl)

    async def ttl(self, key: str) -> int:
        entry = self.store.get(key)
        if not entry: return 0
        _, exp_ts = entry
        return max(int(exp_ts - time()), 0) if exp_ts else 0

    async def _cleanup(self):
        while True:
            await asyncio.sleep(self.cleanup_interval)
            now = time()
            keys = [k for k, (_, ts) in self.store.items() if ts and ts < now]
            for k in keys:
                del self.store[k]
                self.locks.pop(k, None)

# ----------------------------
# ASGI Rate Limiter Middleware
# ----------------------------
class RateLimiterMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        rules: dict,
        backend: RateLimitBackend,
        backoff_threshold: int = 3,
        max_backoff: int = 60,
        key_func: Callable = lambda scope: scope.get("client")[0] if scope.get("client") else "anon"
    ):
        self.app = app
        self.backend = backend
        self.backoff_threshold = backoff_threshold
        self.max_backoff = max_backoff
        self.key_func = key_func
        # Sorted rules by prefix length (longest first)
        self.sorted_rules = sorted(rules.items(), key=lambda x: len(x[0]), reverse=True)

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope["path"]
        user_key = self.key_func(scope)
        exceeded_ttls = []
        limit_headers = {}
        matched = False

        for prefix, cfg in self.sorted_rules:
            if path.startswith(prefix):
                matched = True
                limit, period = cfg.get("limit", 1), cfg.get("period", 1)
                key = f"ratelimit:{user_key}:{prefix}"
                violations_key = f"{key}:violations"

                count = await self.backend.incr(key, expire=period)
                remaining = max(limit - count, 0)
                limit_headers = {
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": str(remaining),
                }

                if count > limit:
                    violations = await self.backend.incr(violations_key, expire=period * 5)
                    backoff = min(period * (2 ** max(0, violations - self.backoff_threshold)), self.max_backoff)
                    await self.backend.expire(key, int(backoff))
                    exceeded_ttls.append(int(backoff))

        if exceeded_ttls:
            retry_after = max(exceeded_ttls)
            response = JSONResponse(
                status_code=429,
                content={"detail": f"Too many requests. Retry in {retry_after}s."},
                headers={**limit_headers, "Retry-After": str(retry_after)}
            )
            await response(scope, receive, send)
            return

        if not matched:
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                for k, v in limit_headers.items():
                    headers.append((k.encode(), v.encode()))
            await send(message)

        await self.app(scope, receive, send_wrapper)
# ----------------------------