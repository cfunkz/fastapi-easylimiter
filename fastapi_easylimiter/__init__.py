import asyncio
import time
from typing import Dict, Optional, List, Tuple
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.responses import JSONResponse
import redis.asyncio as redis_async

# -----------------------------
# Trusted Proxy IP Extractor
# -----------------------------
def real_ip_extractor(trusted_proxies: Optional[List[str]] = None):
    trusted = set(trusted_proxies or [])

    def get_ip(scope: Scope) -> str:
        client_ip = scope.get("client", ("unknown", 0))[0]

        # Use X-Forwarded-For only if caller is trusted
        headers = dict(scope.get("headers") or [])
        xff = headers.get(b"x-forwarded-for")
        if not xff or client_ip not in trusted:
            return client_ip

        chain = [ip.strip() for ip in xff.decode().split(",") if ip.strip()]
        for ip in reversed(chain):
            if ip not in trusted:
                return ip
        return client_ip

    return get_ip

# -----------------------------
# Redis Backend with Fixed Window Counter
# -----------------------------
class AsyncRedisBackend:
    LUA_SCRIPT = """
    local key = KEYS[1]
    local limit = tonumber(ARGV[1])
    local period = tonumber(ARGV[2])

    local count = redis.call('INCR', key)
    if count == 1 then
        redis.call('EXPIRE', key, period)
    end

    local ttl = redis.call('TTL', key)
    if ttl < 0 then ttl = period end

    return {count, ttl}
    """

    def __init__(self, redis_client: redis_async.Redis):
        self.redis = redis_client
        self.script = redis_client.register_script(self.LUA_SCRIPT)

    async def incr(self, key: str, limit: int, period: int):
        count, ttl = await self.script(keys=[key], args=[limit, period])
        return int(count), int(ttl)

# -----------------------------
# In-Memory Backend (Dev Only)
# -----------------------------
class InMemoryBackend:
    """
    Simple async in-memory rate limiter for development/testing.
    Mirrors the AsyncRedisBackend API.
    """

    def __init__(self, cleanup_interval: int = 10):
        # key -> (count, expire_at)
        self.store: Dict[str, Tuple[int, float]] = {}
        # key -> asyncio.Lock
        self.locks: Dict[str, asyncio.Lock] = {}
        self.cleanup_interval = cleanup_interval
        asyncio.create_task(self._cleanup_loop())

    async def _lock(self, key: str) -> asyncio.Lock:
        if key not in self.locks:
            self.locks[key] = asyncio.Lock()
        return self.locks[key]

    async def incr(self, key: str, limit: int, period: int):
        now = time.time()
        async with await self._lock(key):
            count, expire_at = self.store.get(key, (0, 0.0))

            if expire_at and now >= expire_at:
                count, expire_at = 0, 0.0

            count += 1
            if period:
                expire_at = now + period

            self.store[key] = (count, expire_at)
            ttl = max(int(expire_at - now), 0) if expire_at else period

            return count, ttl

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(self.cleanup_interval)
            now = time.time()
            keys_to_delete = [k for k, (_, exp) in self.store.items() if exp and exp <= now]
            for k in keys_to_delete:
                self.store.pop(k, None)
                self.locks.pop(k, None)

# -----------------------------
# RateLimiter Middleware
# -----------------------------
class RateLimiterMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        rules: Dict[str, Dict[str, int]],
        backend,
        trusted_proxies: Optional[List[str]] = None,
    ):
        """
        :param app: FastAPI or Starlette app
        :param rules: dict like {"/": {"limit": 1000, "period": 60}, "/login": {"limit": 10, "period": 60}}
        :param backend: AsyncRedisBackend or InMemoryBackend
        :param trusted_proxies: list of IPs allowed to set X-Forwarded-For
        """
        self.app = app
        self.backend = backend
        self.get_ip = real_ip_extractor(trusted_proxies)

        # Pre-sort longest prefix first for deterministic matching
        self.rules = sorted(
            [(prefix, cfg["limit"], cfg["period"]) for prefix, cfg in rules.items()],
            key=lambda x: len(x[0]),
            reverse=True,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope["path"]
        ip = self.get_ip(scope)

        headers = {}
        retry_after = 0
        exceeded = False

        # Iterate through all matching prefixes (longest first)
        for prefix, limit, period in self.rules:
            if path.startswith(prefix):
                key = f"rl:{ip}:{prefix}"
                count, ttl = await self.backend.incr(key, limit, period)

                headers.update({
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": str(max(limit - count, 0)),
                    "X-RateLimit-Reset": str(ttl),
                })

                if count > limit:
                    exceeded = True
                    retry_after = max(retry_after, ttl)  # use max TTL for combined rules

        if exceeded:
            resp = JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded. Retry after {retry_after}s."},
                headers={**headers, "Retry-After": str(retry_after)},
            )
            return await resp(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                h = message.setdefault("headers", [])
                for k, v in headers.items():
                    h.append((k.encode(), v.encode()))
            await send(message)

        await self.app(scope, receive, send_with_headers)
