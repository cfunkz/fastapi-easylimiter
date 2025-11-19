# Copyright (c) 2025 cFunkz. All rights reserved.
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Copyright (c) 2025 cFunkz. All rights reserved.
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import asyncio
from typing import Dict, Optional, List, Tuple
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.responses import JSONResponse
import redis.asyncio as redis_async
import ipaddress

# -----------------------------
# Cloudflare IPs (UPDATED: 19/11/2025)
# -----------------------------
CLOUDFLARE_NETWORKS = [
    ipaddress.ip_network(cidr) for cidr in {
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
    }
]

def _ip_in_networks(ip_str: str, networks) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in networks)
    except ValueError:
        return False

# -----------------------------
# Extractor
# -----------------------------
def get_real_ip(trusted_proxies: Optional[List[str]] = None, *, cloudflare: bool = False):
    trusted_networks = [ipaddress.ip_network(p) for p in (trusted_proxies or [])]
    if cloudflare:
        trusted_networks.extend(CLOUDFLARE_NETWORKS)

    def extractor(scope: Scope) -> str:
        headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
        client_ip = scope.get("client", ("", None))[0]

        # 1. CF-Connecting-IP (only if direct client is real Cloudflare)
        if cloudflare and client_ip and "cf-connecting-ip" in headers:
            if _ip_in_networks(client_ip, CLOUDFLARE_NETWORKS):
                return headers["cf-connecting-ip"].strip()

        # 2. X-Forwarded-For: trust only the right-most non-trusted IP
        if "x-forwarded-for" in headers:
            ips = [ip.strip() for ip in headers["x-forwarded-for"].split(",")]
            for ip in reversed(ips):
                if ip and not _ip_in_networks(ip, trusted_networks):
                    return ip

        # 3. Direct client (if not behind trusted proxy)
        if client_ip and not _ip_in_networks(client_ip, trusted_networks):
            return client_ip

        return "unknown"
    return extractor

# -----------------------------
# Redis Backend
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
    return count .. ":" .. ttl
    """

    def __init__(self, redis_client: redis_async.Redis, *, fail_closed: bool = True):
        self.redis = redis_client
        self.fail_closed = fail_closed
        self.script = redis_client.register_script(self.LUA_SCRIPT)

    async def incr(self, key: str, limit: int, period: int) -> Tuple[int, int]:
        try:
            raw = await asyncio.wait_for(
                self.script(keys=[key], args=[limit, period]), timeout=0.5
            )
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode()
            count_str, ttl_str = raw.split(":", 1)
            return int(count_str), int(ttl_str)
        except Exception as exc:
            if not self.fail_closed:
                return 0, 0  # explicit fail-open for testing/dev
            raise RuntimeError("Rate limiter unavailable") from exc

# -----------------------------
# In-Memory Backend (unchanged, dev only)
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
                del self.store[k]
                self.locks.pop(k, None)

# -----------------------------
# RateLimiterMiddleware
# -----------------------------
class RateLimiterMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        rules: Dict[str, Dict[str, int]],
        backend,
        trusted_proxies: Optional[List[str]] = None,
        cloudflare: bool = False,
    ):
        self.app = app
        self.backend = backend
        self.get_ip = get_real_ip(trusted_proxies, cloudflare=cloudflare)

        # longest → shortest
        self.sorted_rules = sorted(
            rules.items(),
            key=lambda x: len(x[0]),
            reverse=True,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope["path"]
        ip = self.get_ip(scope)

        # Find ALL matching prefixes (longest first)
        matching = []
        for prefix, cfg in self.sorted_rules:
            if path.startswith(prefix):
                key = f"rl:{ip}:{prefix}"
                matching.append((key, cfg["limit"], cfg["period"]))

        if not matching:
            return await self.app(scope, receive, send)

        # Increment ALL matching rules in parallel
        results = await asyncio.gather(
            *[self.backend.incr(k, l, p) for k, l, p in matching],
            return_exceptions=True,
        )

        headers = {}
        retry_after = 0
        exceeded = False

        for (key, limit, period), result in zip(matching, results):
            if isinstance(result, BaseException):
                # fail-closed on any Redis error
                resp = JSONResponse(status_code=503, content={"detail": "Service unavailable"})
                return await resp(scope, receive, send)

            count, ttl = result
            remaining = max(0, limit - count)

            headers = {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(ttl),
            }

            if count > limit:
                exceeded = True
                retry_after = max(retry_after, ttl)
                break  # longest (most specific) exceeded → block immediately

        if exceeded:
            resp = JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded. Retry after {retry_after}s"},
                headers={**headers, "Retry-After": str(retry_after)},
            )
            return await resp(scope, receive, send)

        # Success – send headers from most specific rule
        async def send_wrapped(message):
            if message["type"] == "http.response.start":
                h = message.setdefault("headers", [])
                for k, v in headers.items():
                    h.append((k.encode(), v.encode()))
            await send(message)

        await self.app(scope, receive, send_wrapped)
