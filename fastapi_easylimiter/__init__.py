import asyncio
import json
from typing import Dict, Optional, List, Tuple
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.responses import JSONResponse
import redis.asyncio as redis_async

# -----------------------------
# Trusted Proxy IP Extractor (Cloudflare + Proxy Safe)
# -----------------------------
def real_ip_extractor(trusted_proxies: Optional[List[str]] = None):
    trusted = set(trusted_proxies or [])
    def get_ip(scope: Scope) -> str:
        headers = dict(scope.get("headers") or [])
        # Cloudflare first
        cf_ip = headers.get(b"cf-connecting-ip")
        if cf_ip:
            return cf_ip.decode().strip()
        client_ip = scope.get("client", ("unknown", 0))[0]
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
# Redis Backend (Fixed Counter)
# -----------------------------
class AsyncRedisBackend:
    LUA_SCRIPT = """
    local key = KEYS[1]
    local limit = tonumber(ARGV[1])
    local period = tonumber(ARGV[2])
    local count = redis.call('INCR', key)
    if count == 1 then redis.call('EXPIRE', key, period) end
    local ttl = redis.call('TTL', key)
    if ttl < 0 then ttl = period end
    return cjson.encode({count, ttl})
    """

    def __init__(self, redis_client: redis_async.Redis):
        self.redis = redis_client
        self.script = redis_client.register_script(self.LUA_SCRIPT)  # Registered once

    async def incr(self, key: str, limit: int, period: int) -> Tuple[int, int]:
        raw = await self.script(keys=[key], args=[limit, period])
        data = json.loads(raw)
        return int(data[0]), int(data[1])

# -----------------------------
# In-Memory Backend (Dev Only)
# -----------------------------
class InMemoryBackend:
    def __init__(self, cleanup_interval: int = 10):
        self.store: Dict[str, Tuple[int, float]] = {}
        self.locks: Dict[str, asyncio.Lock] = {}
        self.cleanup_interval = cleanup_interval
        asyncio.create_task(self._cleanup_loop())

    async def _lock(self, key: str) -> asyncio.Lock:
        if key not in self.locks:
            self.locks[key] = asyncio.Lock()
        return self.locks[key]

    async def incr(self, key: str, limit: int, period: int) -> Tuple[int, int]:
        now = asyncio.get_event_loop().time()
        async with await self._lock(key):
            count, expire_at = self.store.get(key, (0, 0.0))
            if expire_at and now >= expire_at:
                count = 0
            count += 1
            if count == 1:
                expire_at = now + period
            self.store[key] = (count, expire_at)
            ttl = max(int(expire_at - now), 0)
            return count, ttl

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(self.cleanup_interval)
            now = asyncio.get_event_loop().time()
            expired = [k for k, (_, exp) in self.store.items() if exp <= now]
            for k in expired:
                self.store.pop(k, None)
                self.locks.pop(k, None)

# -----------------------------
# RateLimiterMiddleware (Global First)
# -----------------------------
class RateLimiterMiddleware:
    GLOBAL_PREFIX = "/"

    def __init__(
        self,
        app: ASGIApp,
        rules: Dict[str, Dict[str, int]],
        backend,
        trusted_proxies: Optional[List[str]] = None,
    ):
        self.app = app
        self.backend = backend
        self.get_ip = real_ip_extractor(trusted_proxies)

        # Sort: longest first → specific wins
        self.rules = sorted(
            [(p, c["limit"], c["period"]) for p, c in rules.items()],
            key=lambda x: len(x[0]), reverse=True
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope["path"]
        ip = self.get_ip(scope)

        # Build matching rules: global first if exists
        global_rule = None
        specific_rules = []
        for prefix, limit, period in self.rules:
            if path.startswith(prefix):
                key = f"rl:{ip}:{prefix}"
                if prefix == self.GLOBAL_PREFIX:
                    global_rule = (key, limit, prefix)
                else:
                    specific_rules.append((key, limit, period, prefix))

        # No rules → allow
        if not global_rule and not specific_rules:
            return await self.app(scope, receive, send)

        # 1. Check GLOBAL first (if exists)
        if global_rule:
            g_key, g_limit, g_prefix = global_rule
            g_count, g_ttl = await self.backend.incr(g_key, g_limit, 60)  # period from rule
            g_remaining = max(g_limit - g_count, 0)
            headers = {
                "X-RateLimit-Limit": str(g_limit),
                "X-RateLimit-Remaining": str(g_remaining),
                "X-RateLimit-Reset": str(g_ttl),
            }
            if g_count > g_limit:
                resp = JSONResponse(
                    status_code=429,
                    content={"detail": f"Global rate limit exceeded. Retry after {g_ttl}s."},
                    headers={**headers, "Retry-After": str(g_ttl)},
                )
                return await resp(scope, receive, send)
            # Global OK → continue to specific
            matching = specific_rules
        else:
            headers = {}
            matching = specific_rules

        # 2. Parallel check SPECIFIC rules (if any)
        if matching:
            tasks = [self.backend.incr(k, l, p) for k, l, p, _ in matching]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            retry_after = 0
            exceeded = False
            for (key, limit, period, prefix), result in zip(matching, results):
                if isinstance(result, BaseException):
                    continue  # Fail-open
                count, ttl = result
                remaining = max(limit - count, 0)
                headers.update({
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(ttl),
                })
                if count > limit:
                    exceeded = True
                    retry_after = max(retry_after, ttl)
                    break  # Specific wins

            if exceeded:
                resp = JSONResponse(
                    status_code=429,
                    content={"detail": f"Rate limit exceeded. Retry after {retry_after}s."},
                    headers={**headers, "Retry-After": str(retry_after)},
                )
                return await resp(scope, receive, send)

        # 3. Success → pass with headers
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                h = message.setdefault("headers", [])
                for k, v in headers.items():
                    h.append((k.encode(), v.encode()))
            await send(message)

        await self.app(scope, receive, send_with_headers)