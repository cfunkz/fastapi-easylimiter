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
import ipaddress
import time
from typing import Dict, Optional, Tuple
from starlette.types import ASGIApp, Scope, Receive, Send
from redis.exceptions import NoScriptError
from starlette.responses import JSONResponse, HTMLResponse
import redis.asyncio as redis_async

# Cloudflare IPs – updated 20/11/2025
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

# Optimized Lua script - atomic and returns correct reset time
LUA_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local count = redis.call("INCR", key)
local ttl = redis.call("TTL", key)

if count == 1 or ttl < 0 then
    redis.call("EXPIRE", key, window)
    ttl = window
end

local reset = now + ttl
local exceeded = count > limit and 1 or 0

return {count, reset, exceeded}
"""


def get_real_ip(trusted_proxies: Optional[list[str]] = None, *, cloudflare: bool = False):
    """Extract real client IP from headers."""
    trusted_proxies = trusted_proxies or []
    trusted_nets = [ipaddress.ip_network(p, strict=False) for p in trusted_proxies]
    cf_nets = CLOUDFLARE_NETWORKS if cloudflare else []

    def extractor(scope: Scope) -> str:
        try:
            headers = {k.decode("latin-1").lower(): v.decode("latin-1") 
                      for k, v in scope.get("headers", [])}
            client_host, _ = scope.get("client") or (None, None)
            if not client_host:
                return "unknown"

            client_ip = ipaddress.ip_address(client_host)

            # CF-Connecting-IP (only from Cloudflare IPs)
            if cloudflare and "cf-connecting-ip" in headers:
                if any(client_ip in net for net in cf_nets):
                    cf_ip = headers["cf-connecting-ip"].strip()
                    try:
                        ipaddress.ip_address(cf_ip)
                        return cf_ip
                    except ValueError:
                        pass

            # X-Forwarded-For (only from trusted proxies)
            if trusted_nets and "x-forwarded-for" in headers:
                for ip_str in reversed(headers["x-forwarded-for"].split(",")):
                    ip_str = ip_str.strip()
                    if ip_str:
                        try:
                            ip = ipaddress.ip_address(ip_str)
                            if not any(ip in net for net in trusted_nets + cf_nets):
                                return ip_str
                        except ValueError:
                            continue

            # Direct connection (not from trusted proxy)
            if not any(client_ip in net for net in trusted_nets + cf_nets):
                return client_host

            return "unknown"
        except Exception:
            return "unknown"

    return extractor


class AsyncRedisBackend:
    def __init__(self, client: redis_async.Redis, *, fail_open: bool = False, eval_timeout: float = 30.0):
        self.client = client
        self.fail_open = fail_open
        self.eval_timeout = eval_timeout
        self.script = client.register_script(LUA_SCRIPT)  # no type issues

    async def incr(self, key: str, limit: int, window: int) -> Tuple[int, int, bool]:
        now = int(time.time())
        try:
            res = await asyncio.wait_for(
                self.script(keys=[key], args=[limit, window, now]),
                timeout=self.eval_timeout
            )
            count, reset, exceeded = int(res[0]), int(res[1]), bool(res[2])
            return count, reset, exceeded
        except NoScriptError:
            # Fallback to EVAL if Redis flushed scripts
            res = await asyncio.wait_for(
                self.client.eval(LUA_SCRIPT, 1, key, limit, window, now), # type: ignore[assignment]
                timeout=self.eval_timeout
            )
            count, reset, exceeded = int(res[0]), int(res[1]), bool(res[2])
            return count, reset, exceeded
        except Exception:
            if self.fail_open:
                return 0, now + window, False
            raise



class InMemoryBackend:
    """Fast in-memory backend for single instance with auto-destroy."""
    
    def __init__(self):
        self.store: Dict[str, Tuple[int, float]] = {}
        self.locks: Dict[str, asyncio.Lock] = {}
        self._cleanup_task = asyncio.create_task(self._cleanup())
        self._destroyed = False

    async def _cleanup(self):
        """Cleanup expired keys every 5 minutes."""
        try:
            while True:
                await asyncio.sleep(300)
                now = time.time()
                expired = [k for k, (_, exp) in self.store.items() if exp <= now]
                for k in expired:
                    self.store.pop(k, None)
                    self.locks.pop(k, None)
        except asyncio.CancelledError:
            pass

    async def incr(self, key: str, limit: int, window: int) -> Tuple[int, int, bool]:
        """Returns (count, reset_timestamp, exceeded). Checks if cleanup task is alive."""
        # Auto-destroy if cleanup task stopped
        if self._cleanup_task.done() and not self._destroyed:
            await self.destroy()

        now = time.time()
        lock = self.locks.setdefault(key, asyncio.Lock())
        
        async with lock:
            count, expiry = self.store.get(key, (0, 0.0))
            if expiry <= now:
                count = 0
                expiry = now + window
            
            count += 1
            self.store[key] = (count, expiry)
            
            return count, int(expiry), count > limit

    async def destroy(self):
        """Cancel cleanup task and clear state."""
        if self._destroyed:
            return
        self._destroyed = True
        self._cleanup_task.cancel()
        try:
            await self._cleanup_task
        except asyncio.CancelledError:
            pass
        self.store.clear()
        self.locks.clear()


class RateLimiterMiddleware:
    
    def __init__(
        self,
        app: ASGIApp,
        backend: (AsyncRedisBackend | InMemoryBackend),
        rules: Dict[str, Dict[str, int]],
        *,
        trusted_proxies: Optional[list[str]] = None,
        cloudflare: bool = False,
        enable_bans: bool = True,
        ban_threshold: int = 15,
        ban_duration: int = 300,
        offense_ttl: int = 900,
        ban_page: Optional[str] = None,
        rate_page: Optional[str] = None,
    ):
        self.app = app
        self.backend = backend
        self.get_ip = get_real_ip(trusted_proxies, cloudflare=cloudflare)
        # Sort by length for correct prefix matching
        self.rules = sorted(rules.items(), key=lambda x: len(x[0]), reverse=True)
        
        self.enable_bans = enable_bans
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self.offense_ttl = offense_ttl
        self.ban_page = ban_page or BAN_PAGE
        self.rate_page = rate_page or RATE_PAGE

    async def _is_banned(self, ip: str) -> Tuple[bool, int]:
        """Check ban status. Returns (is_banned, ttl_seconds)."""
        key = f"ban:{ip}"
        
        if isinstance(self.backend, AsyncRedisBackend):
            ttl = await self.backend.client.ttl(key)
            return ttl > 0, max(0, ttl)
        
        _, exp = self.backend.store.get(key, (0, 0.0))
        ttl = max(0, int(exp - time.time()))
        return ttl > 0, ttl

    async def _add_offense(self, ip: str):
        """Record offense and ban if threshold exceeded."""
        if not self.enable_bans:
            return
        
        okey = f"offense:{ip}"
        bkey = f"ban:{ip}"
        now = time.time()

        if isinstance(self.backend, AsyncRedisBackend):
            pipe = self.backend.client.pipeline()
            pipe.incr(okey)
            pipe.expire(okey, self.offense_ttl)
            count, _ = await pipe.execute()
            
            if count >= self.ban_threshold:
                await self.backend.client.setex(bkey, self.ban_duration, "1")
        else:
            lock = self.backend.locks.setdefault(okey, asyncio.Lock())
            async with lock:
                count, exp = self.backend.store.get(okey, (0, 0.0))
                if exp <= now:
                    count = 0
                
                count += 1
                self.backend.store[okey] = (count, now + self.offense_ttl)
                
                if count >= self.ban_threshold:
                    self.backend.store[bkey] = (1, now + self.ban_duration)

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        ip = self.get_ip(scope)
        path = scope["path"]

        # Check ban
        is_banned, ban_ttl = await self._is_banned(ip)
        if is_banned:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            
            headers = {"Retry-After": str(ban_ttl)}
            accept = next((v.decode("latin-1") for k, v in scope.get("headers", []) 
                          if k.decode("latin-1").lower() == "accept"), "")
            
            if "text/html" in accept or not accept:
                return await HTMLResponse(self.ban_page, 403, headers)(scope, receive, send)
            return await JSONResponse({"detail": "Temporarily banned"}, 403, headers)(
                scope, receive, send)

        # Find matching rules
        tasks = []
        for prefix, cfg in self.rules:
            if path.startswith(prefix):
                tasks.append((f"rl:{ip}:{prefix}", cfg["limit"], cfg["period"]))

        if not tasks:
            return await self.app(scope, receive, send)

        # Check all limits concurrently
        try:
            results = await asyncio.gather(*(
                self.backend.incr(k, lim, per) for k, lim, per in tasks
            ))
        except Exception:
            # Fail open on backend error
            return await self.app(scope, receive, send)

        # Process results
        exceeded = False
        retry_after = 0
        headers = {}

        for (_, limit, _), (count, reset, over) in zip(tasks, results):
            remaining = max(0, limit - count)
            if not headers or remaining < int(headers["X-RateLimit-Remaining"]):
                headers = {
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(reset),
                }
            if over:
                exceeded = True
                retry_after = max(retry_after, reset - int(time.time()))

        if exceeded:
            await self._add_offense(ip)
            headers["Retry-After"] = str(retry_after)
            
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            
            accept = next((v.decode("latin-1") for k, v in scope.get("headers", []) 
                          if k.decode("latin-1").lower() == "accept"), "")
            
            if "text/html" in accept or not accept:
                return await HTMLResponse(
                    self.rate_page.format(retry_after=retry_after), 429, headers
                )(scope, receive, send)
            
            return await JSONResponse(
                {"detail": f"Rate limit exceeded. Retry after {retry_after}s"},
                429, headers
            )(scope, receive, send)

        # Pass through with headers
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                h = message.setdefault("headers", [])
                for k, v in headers.items():
                    h.append((k.encode("latin-1"), v.encode("latin-1")))
            await send(message)

        await self.app(scope, receive, send_with_headers)


BAN_PAGE = """
<body style="margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px system-ui,sans-serif;">
    <div style="width:500px;padding:30px;background:#161b22;border-radius:12px;text-align:center;border:2px solid #30363d;">
        <h1 style="color:#f85149;margin-bottom:12px;">403 Access Blocked</h1>
        <p>Too many requests from your IP.</p>
        <p style="color:#8b949e;">Please try again later.</p>
        <p style="margin-top:16px;font-size:12px;color:#8b949e;">
            <a href="https://github.com/cfunkz/fastapi-easylimiter" style="color:green;text-decoration:none;">EasyLimiter</a>
        </p>
    </div>
</body>
"""

RATE_PAGE = """
<body style="margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px system-ui,sans-serif;">
    <div style="width:500px;padding:30px;background:#161b22;border-radius:12px;text-align:center;border:2px solid #30363d;">
        <h1 style="color:#f85149;margin-bottom:12px;">429 Rate Limit Exceeded</h1>
        <p>You have made too many requests.</p>
        <p style="color:#8b949e;">Please retry again in a minute.</p>
        <p style="margin-top:16px;font-size:12px;color:#8b949e;">
            <a href="https://github.com/cfunkz/fastapi-easylimiter" style="color:green;text-decoration:none;">EasyLimiter</a>
        </p>
    </div>
</body>
"""
