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
import time

# Cloudflare IPs – updated 20/11/2025 (source: https://www.cloudflare.com/ips/)
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
    trusted_proxies = trusted_proxies or []
    trusted_nets = [ipaddress.ip_network(p) for p in trusted_proxies]
    cf_nets = CLOUDFLARE_NETWORKS if cloudflare else []

    def extractor(scope: Scope) -> str:
        try:
            headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
            client_host, _ = scope.get("client") or (None, None)
            if not client_host:
                return "unknown"

            client_ip = ipaddress.ip_address(client_host)

            # CF-Connecting-IP only if client is trusted CF proxy
            if cloudflare and "cf-connecting-ip" in headers:
                if any(client_ip in net for net in cf_nets):
                    return headers["cf-connecting-ip"]

            # X-Forwarded-For only if we have trusted proxies configured
            if trusted_proxies and "x-forwarded-for" in headers:
                for ip_str in reversed(headers["x-forwarded-for"].split(",")):
                    ip_str = ip_str.strip()
                    if not ip_str:
                        continue
                    ip = ipaddress.ip_address(ip_str)
                    if not any(ip in net for net in trusted_nets):
                        return ip_str

            # Direct client if not behind trusted proxy
            if not any(client_ip in net for net in trusted_nets):
                return client_host

            return "unknown"
        except Exception:
            return "unknown"

    return extractor

LUA_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

local c = redis.call("INCR", key)
if c == 1 then redis.call("EXPIRE", key, window) end

local ttl = redis.call("TTL", key)
if ttl < 0 then ttl = window end

if c > limit then
    return {c, ttl, 1}
else
    return {c, ttl, 0}
end
"""

class AsyncRedisBackend:
    def __init__(self, client: redis_async.Redis, *, fail_closed: bool = True):
        self.client = client
        self.fail_closed = fail_closed
        self.script = client.register_script(LUA_SCRIPT)

    async def incr(self, key: str, limit: int, window: int) -> Tuple[int, int, bool]:
        try:
            res = await asyncio.wait_for(
                self.script(keys=[key], args=[limit, window]), timeout=1.0
            )
            count = int(res[0])
            ttl = int(res[1])
            exceeded = res[2] == 1
            return count, ttl, exceeded
        except Exception:
            if not self.fail_closed:
                return 0, 0, False
            raise RuntimeError("Rate limiter unavailable")

class InMemoryBackend:
    def __init__(self):
        self.store: Dict[str, Tuple[int, float]] = {}
        self.locks: Dict[str, asyncio.Lock] = {}
        self._cleanup = asyncio.create_task(self._cleanup_loop())

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(300)
            now = time.time()
            expired = [k for k, (c, e) in self.store.items() if e <= now]
            for k in expired:
                self.store.pop(k, None)
                self.locks.pop(k, None)

    async def incr(self, key: str, limit: int, window: int) -> Tuple[int, int, bool]:
        now = time.time()
        lock = self.locks.setdefault(key, asyncio.Lock())
        async with lock:
            count, expiry = self.store.get(key, (0, 0.0))
            if expiry <= now:
                count = 0
            count += 1
            if count == 1:
                expiry = now + window
            self.store[key] = (count, expiry)
            ttl = max(0, int(expiry - now))
            return count, ttl, count > limit

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
        ban_page: Optional[str] = None,
        rate_page: Optional[str] = None,
    ):
        self.app = app
        self.backend = backend
        self.get_ip = get_real_ip(trusted_proxies, cloudflare=cloudflare)
        self.rules = sorted(rules.items(), key=lambda x: len(x[0]), reverse=True)

        self.enable_bans = enable_bans
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self.offenses_ttl = offenses_ttl
        self.ban_page = (ban_page or BAN_PAGE).strip()
        self.rate_page = (rate_page or RATE_PAGE).strip()

    async def _banned(self, ip: str) -> bool:
        key = f"ban:{ip}"
        if isinstance(self.backend, AsyncRedisBackend):
            return await self.backend.client.exists(key)
        _, exp = self.backend.store.get(key, (0, 0.0))
        return exp > time.time()

    async def _offense(self, ip: str):
        if not self.enable_bans:
            return
        okey = f"offenses:{ip}"
        bkey = f"ban:{ip}"
        now = time.time()

        if isinstance(self.backend, AsyncRedisBackend):
            pipe = self.backend.client.pipeline()
            pipe.incr(okey)
            pipe.expire(okey, self.offenses_ttl)
            count = (await pipe.execute())[0]
            if count >= self.ban_threshold:
                await self.backend.client.setex(bkey, self.ban_duration, "1")
        else:
            lock = self.backend.locks.setdefault(okey, asyncio.Lock())
            async with lock:
                c, exp = self.backend.store.get(okey, (0, 0.0))
                if exp <= now:
                    c = 0
                c += 1
                self.backend.store[okey] = (c, now + self.offenses_ttl)
                if c >= self.ban_threshold:
                    self.backend.store[bkey] = (1, now + self.ban_duration)

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] not in ("http", "websocket"): # NEW: WebSocket support
                return await self.app(scope, receive, send)

        ip = self.get_ip(scope)
        path = scope["path"]

        if await self._banned(ip):
            headers = {"Retry-After": str(self.ban_duration)}
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            # HTTP only from here
            accept = next(
                (v.decode() for k, v in scope.get("headers", []) if k.decode().lower() == "accept"),
                "")
            if "text/html" in accept or not accept:
                return await HTMLResponse(self.ban_page, 429, headers)(scope, receive, send)
            return await JSONResponse(
                {"detail": "Temporarily banned"}, 429, headers)(scope, receive, send)

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

        for (_, limit, _), (count, ttl, over) in zip(tasks, results):
            remaining = max(0, limit - count)
            ratelimit_headers = {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(ttl or 1),
            }
            if over:
                exceeded = True
                retry_after = max(retry_after, ttl)

        if exceeded:
            await self._offense(ip)
            ratelimit_headers["Retry-After"] = str(retry_after)
            accept = next((v.decode() for k, v in scope.get("headers", []) if k.decode().lower() == "accept"), "")
            if "text/html" in accept or not accept:
                return await HTMLResponse(RATE_PAGE.format(retry_after=retry_after), 429, ratelimit_headers)(scope, receive, send)
            return await JSONResponse({"detail": f"Rate limit exceeded. Retry after {retry_after}s"}, 429, ratelimit_headers)(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                h = message.setdefault("headers", [])
                for k, v in ratelimit_headers.items():
                    h.append((k.encode(), v.encode()))
            await send(message)

        await self.app(scope, receive, send_with_headers)

BAN_PAGE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Blocked</title><style>body{margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px/1.5 system-ui,sans-serif}.card{max-width:360px;padding:32px;background:#161b22;border:1px solid #30363d;border-radius:12px;text-align:center}h1{margin:0 0 12px;font-size:22px;color:#f85149}p{margin:8px 0 0;font-size:15px}</style></head><body><div class="card"><h1>Access Blocked</h1><p>Too many requests from your IP.</p><p>Please try again later.</p></div></body></html>"""
RATE_PAGE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Rate Limit Exceeded</title><style>body{margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px/1.5 system-ui,sans-serif}.card{max-width:360px;padding:32px;background:#161b22;border:1px solid #30363d;border-radius:12px;text-align:center}h1{margin:0 0 12px;font-size:22px;color:#f85149}p{margin:8px 0 0;font-size:15px}</style></head><body><div class="card"><h1>Rate Limit Exceeded</h1><p>You have made too many requests.</p><p>Please retry after {retry_after} seconds.</p></div></body></html>"""
