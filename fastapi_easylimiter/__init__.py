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
from typing import Dict, Optional, Tuple
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.responses import JSONResponse, HTMLResponse
import redis.asyncio as redis_async
import ipaddress

# Cloudflare IPs – *UPDATED* 19/11/2025 NEW: Cloudflare CIDR ranges
CLOUDFLARE_NETWORKS = [
    ipaddress.ip_network(c) for c in {
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
    }
]

def get_real_ip(trusted_proxies: Optional[list[str]] = None, *, cloudflare: bool = False):
    trusted = [ipaddress.ip_network(p) for p in (trusted_proxies or [])]
    if cloudflare:
        trusted.extend(CLOUDFLARE_NETWORKS)

    def extractor(scope: Scope) -> str:
        headers = dict(scope.get("headers", []))
        headers = {k.decode(): v.decode() for k, v in headers.items()}
        client = scope.get("client", (None, None))[0]

        # CF direct
        if cloudflare and client and headers.get("cf-connecting-ip"):
            if ipaddress.ip_address(client) in CLOUDFLARE_NETWORKS:
                return headers["cf-connecting-ip"]

        # X-Forwarded-For – rightmost untrusted
        if "x-forwarded-for" in headers:
            for ip in reversed(headers["x-forwarded-for"].split(",")):
                ip = ip.strip()
                if ip and ipaddress.ip_address(ip) not in trusted:
                    return ip

        # Direct client
        if client and ipaddress.ip_address(client) not in trusted:
            return client

        return "unknown"
    return extractor

# ----------------------------- Backends -----------------------------
class AsyncRedisBackend:
    LUA = """
    local c = redis.call('INCR', KEYS[1])
    if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
    local t = redis.call('TTL', KEYS[1])
    if t < 0 then t = tonumber(ARGV[2]) end
    return c .. ':' .. t
    """

    def __init__(self, client: redis_async.Redis, *, fail_closed: bool = True):
        self.client = client
        self.fail_closed = fail_closed
        self.script = client.register_script(self.LUA)

    async def incr(self, key: str, limit: int, window: int) -> Tuple[int, int]:
        try:
            raw = await asyncio.wait_for(
                self.script(keys=[key], args=[limit, window]), timeout=0.5
            )
            raw = raw.decode() if isinstance(raw, (bytes, bytearray)) else raw
            count, ttl = map(int, raw.split(":"))
            return count, ttl
        except Exception:
            if not self.fail_closed:
                return 0, 0
            raise RuntimeError("Rate limiter unavailable")

class InMemoryBackend:
    def __init__(self):
        self.store: Dict[str, Tuple[int, float]] = {}
        self.locks: Dict[str, asyncio.Lock] = {}

    async def _lock(self, key: str) -> asyncio.Lock:
        return self.locks.setdefault(key, asyncio.Lock())

    async def incr(self, key: str, limit: int, window: int) -> Tuple[int, int]:
        now = asyncio.get_event_loop().time()
        async with await self._lock(key):
            count, expiry = self.store.get(key, (0, 0.0))
            if expiry <= now:
                count = 0
            count += 1
            if count == 1:
                expiry = now + window
            self.store[key] = (count, expiry)
            return count, max(int(expiry - now), 0)

# ----------------------------- Middleware -----------------------------
class RateLimiterMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        rules: Dict[str, Dict[str, int]],
        backend,
        *,
        trusted_proxies: Optional[list[str]] = None,
        cloudflare: bool = False,
        enable_bans: bool = True,
        ban_threshold: int = 10,
        ban_duration: int = 300,
        offenses_ttl: int = 1800,
    ):
        self.app = app
        self.backend = backend
        self.get_ip = get_real_ip(trusted_proxies, cloudflare=cloudflare)
        self.rules = sorted(rules.items(), key=lambda x: len(x[0]), reverse=True)
        self.is_redis = isinstance(backend, AsyncRedisBackend)

        self.enable_bans = enable_bans
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self.offenses_ttl = offenses_ttl

    async def _banned(self, ip: str) -> bool:
        key = f"ban:{ip}"
        if self.is_redis:
            return bool(await self.backend.client.exists(key))
        _, exp = self.backend.store.get(key, (0, 0.0))
        return exp > asyncio.get_event_loop().time()

    async def _offense(self, ip: str):
        if not self.enable_bans:
            return
        okey, bkey = f"offenses:{ip}", f"ban:{ip}"
        now = asyncio.get_event_loop().time()

        if self.is_redis:
            pipe = self.backend.client.pipeline()
            pipe.incr(okey)
            pipe.expire(okey, self.offenses_ttl)
            count = (await pipe.execute())[0]
            if count >= self.ban_threshold:
                await self.backend.client.setex(bkey, self.ban_duration, "1")
        else:
            async with await self.backend._lock(okey):
                c, exp = self.backend.store.get(okey, (0, 0.0))
                if exp <= now:
                    c = 0
                c += 1
                self.backend.store[okey] = (c, now + self.offenses_ttl)
                if c >= self.ban_threshold:
                    self.backend.store[bkey] = (1, now + self.ban_duration)

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        ip = self.get_ip(scope)
        path = scope["path"]

        if await self._banned(ip):
            accept = next((v.decode() for k,v in scope.get("headers",[]) if k.decode().lower()=="accept"), "")
            if "text/html" in accept or not accept:
                return await HTMLResponse(
                    """
                    <!DOCTYPE html>
                    <html lang="en"><head>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <title>Temporarily Blocked</title>
                        <style>
                            body{margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px/1.5 system-ui,-apple-system,sans-serif}
                            .card{max-width:360px;width:100%;padding:32px;background:#161b22;border:1px solid #30363d;border-radius:0;text-align:center}
                            h1{margin:0 0 12px;font-size:22px;color:#f85149}
                            p{margin:8px 0 0;font-size:15px}
                            small{margin-top:24px;display:block;font-size:12px;color:#8b949e}
                        </style>
                    </head><body>
                        <div class="card">
                            <h1>Access Blocked</h1>
                            <p>Too many requests from your IP.</p>
                            <p>Please try again later.</p>
                            <small>Blocked by <a href="https://github.com/cfunkz/fastapi-easylimiter" style="color:green;text-decoration:none">fastapi-easylimiter</a></small>
                        </div>
                    </body></html>
                    """,
                    status_code=429,
                    headers={"Retry-After": str(self.ban_duration)},
                )(scope, receive, send)
            else:
                return await JSONResponse(  # API clients
                    {"detail": "Temporarily banned. Too many requests."},
                    status_code=429,
                    headers={"Retry-After": str(self.ban_duration)}
                )(scope, receive, send)

        # Match rules (longest first)
        tasks = []
        for prefix, cfg in self.rules:
            if path.startswith(prefix):
                tasks.append((f"rl:{ip}:{prefix}", cfg["limit"], cfg["period"]))

        if not tasks:
            return await self.app(scope, receive, send)

        results = await asyncio.gather(*(self.backend.incr(k, l, p) for k, l, p in tasks))

        ratelimit_headers = {}
        retry_after = 0
        exceeded = False

        for (_, limit, _), (count, ttl) in zip(tasks, results):
            remaining = max(0, limit - count)
            ratelimit_headers = {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(ttl),
            }
            if count > limit:
                exceeded = True
                retry_after = max(retry_after, ttl)

        if exceeded:
            await self._offense(ip)
            return await JSONResponse(
                {"detail": f"Rate limit exceeded. Retry after {retry_after}s"},
                status_code=429,
                headers={**ratelimit_headers, "Retry-After": str(retry_after)}
            )(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                h = message.setdefault("headers", [])
                for k, v in ratelimit_headers.items():
                    h.append((k.encode(), v.encode()))
            await send(message)

        await self.app(scope, receive, send_with_headers)
