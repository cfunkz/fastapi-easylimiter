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

# Cloudflare IPs – updated 21/11/2025
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

# Private/reserved IP ranges that should never be trusted from CF-Connecting-IP
PRIVATE_NETWORKS = [
    ipaddress.ip_network(p) for p in {
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
        "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"
    }
]

# Fixed Lua script
LUA_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local count = redis.call("INCR", key)
local ttl = redis.call("TTL", key)

if ttl == -1 then
    redis.call("EXPIRE", key, window)
    ttl = window
end

local reset = now + ttl
local exceeded = count > limit and 1 or 0

return {count, reset, exceeded}
"""


BAN_PAGE = '<body style="margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px system-ui,sans-serif"><div style="width:500px;padding:30px;background:#161b22;border-radius:12px;text-align:center;border:2px solid #30363d"><h1 style="color:#f85149;margin-bottom:12px">403 Access Blocked</h1><p>Too many requests from your IP.</p><p style="color:#8b949e">Please try again later.</p><p style="margin-top:16px;font-size:12px;color:#8b949e"><a href="https://github.com/cfunkz/fastapi-easylimiter" style="color:green;text-decoration:none">EasyLimiter</a></p></div></body>'

RATE_PAGE_TEMPLATE = '<body style="margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px system-ui,sans-serif"><div style="width:500px;padding:30px;background:#161b22;border-radius:12px;text-align:center;border:2px solid #30363d"><h1 style="color:#f85149;margin-bottom:12px">429 Rate Limit Exceeded</h1><p>You have made too many requests.</p><p style="color:#8b949e">Please retry in {retry} seconds.</p><p style="margin-top:16px;font-size:12px;color:#8b949e"><a href="https://github.com/cfunkz/fastapi-easylimiter" style="color:green;text-decoration:none">EasyLimiter</a></p></div></body>'


def is_valid_single_ip(ip_str: str) -> bool:
    """Validate that string is a single valid IP address (no commas, spaces, etc)."""
    if not ip_str or "," in ip_str or " " in ip_str or "\r" in ip_str or "\n" in ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_public_ip(ip_str: str) -> bool:
    """Check if IP is public (not private/reserved/loopback)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def get_real_ip(trusted_proxies: Optional[list[str]] = None, *, cloudflare: bool = False):
    """
    Extract real client IP from headers with enhanced security.
    
    Critical security properties:
    1. X-Forwarded-For is walked LEFT-TO-RIGHT, peeling trusted proxies from the RIGHT
    2. CF-Connecting-IP only accepted if it's a public IP
    3. Returns (ip, is_validated) where is_validated=True means IP came from trusted source
    """
    trusted_proxies = trusted_proxies or []
    trusted_nets = [ipaddress.ip_network(p, strict=False) for p in trusted_proxies]
    cf_nets = CLOUDFLARE_NETWORKS if cloudflare else []

    def extractor(scope: Scope) -> Tuple[str, bool]:
        """Returns (ip, is_validated) where is_validated indicates IP came from trusted source."""
        try:
            # SECURITY FIX: Sanitize header parsing to prevent CRLF injection
            headers = {}
            for k, v in scope.get("headers", []):
                try:
                    key = k.decode("latin-1").lower()
                    val = v.decode("latin-1")
                    # Reject headers with CRLF
                    if "\r" in key or "\n" in key or "\r" in val or "\n" in val:
                        continue
                    headers[key] = val
                except (UnicodeDecodeError, AttributeError):
                    continue

            client_host, _ = scope.get("client") or (None, None)
            if not client_host:
                return "unknown", False

            client_ip = ipaddress.ip_address(client_host)

            # CF-Connecting-IP (only from Cloudflare IPs) - HARDENED
            if cloudflare and "cf-connecting-ip" in headers:
                if any(client_ip in net for net in cf_nets):
                    cf_ip = headers["cf-connecting-ip"].strip()
                    # SECURITY: Validate it's a single PUBLIC IP
                    if is_valid_single_ip(cf_ip) and is_public_ip(cf_ip):
                        return cf_ip, True  # Validated by Cloudflare

            # X-Forwarded-For (only from trusted proxies) - FIXED PARSING
            if (trusted_nets or cf_nets) and "x-forwarded-for" in headers:
                all_trusted = trusted_nets + cf_nets
                xff_ips = [ip.strip() for ip in headers["x-forwarded-for"].split(",")]
                
                # CRITICAL FIX: Walk forward (left-to-right), peel from right
                # The rightmost IP should be the last proxy, work backwards to find first untrusted
                for i in range(len(xff_ips) - 1, -1, -1):
                    ip_str = xff_ips[i]
                    if not ip_str:
                        continue
                    
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        # If this IP is NOT in trusted networks, it's the real client
                        if not any(ip in net for net in all_trusted):
                            return ip_str, True  # Validated through trusted proxy chain
                        # If it IS trusted, keep peeling backwards
                    except ValueError:
                        # Invalid IP format - stop here and use direct connection
                        break

            # Direct connection (not from trusted proxy)
            if not any(client_ip in net for net in trusted_nets + cf_nets):
                return client_host, False  # Direct connection, not validated

            # Fell through - client is from trusted proxy but no valid XFF
            return "unknown", False
        except Exception:
            return "unknown", False

    return extractor


class AsyncRedisBackend:
    def __init__(
        self, 
        client: redis_async.Redis, 
        *, 
        fail_open: bool = False, 
        eval_timeout: float = 30.0,
        key_prefix: str = ""
    ):
        self.client = client
        self.fail_open = fail_open
        self.eval_timeout = eval_timeout
        self.key_prefix = key_prefix
        self.script = client.register_script(LUA_SCRIPT)

    def _prefix_key(self, key: str) -> str:
        """Add namespace prefix to keys."""
        return f"{self.key_prefix}{key}" if self.key_prefix else key

    async def incr(self, key: str, limit: int, window: int) -> Tuple[int, int, bool]:
        now = int(time.time())
        prefixed_key = self._prefix_key(key)
        try:
            res = await asyncio.wait_for(
                self.script(keys=[prefixed_key], args=[limit, window, now]),
                timeout=self.eval_timeout
            )
            count, reset, exceeded = int(res[0]), int(res[1]), bool(res[2])
            return count, reset, exceeded
        except NoScriptError:
            # Fallback to EVAL if Redis flushed scripts
            res = await asyncio.wait_for(
                self.client.eval(LUA_SCRIPT, 1, prefixed_key, limit, window, now), # type: ignore[assignment]
                timeout=self.eval_timeout
            )
            count, reset, exceeded = int(res[0]), int(res[1]), bool(res[2])
            return count, reset, exceeded
        except Exception:
            if self.fail_open:
                return 0, now + window, False
            raise

    async def ttl(self, key: str) -> int:
        """Get TTL for a key."""
        return await self.client.ttl(self._prefix_key(key))

    async def setex(self, key: str, seconds: int, value: str):
        """Set key with expiry."""
        await self.client.setex(self._prefix_key(key), seconds, value)

    async def incr_with_expire(self, key: str, expire: int) -> int:
        """Increment key and set expiry atomically."""
        prefixed_key = self._prefix_key(key)
        pipe = self.client.pipeline()
        pipe.incr(prefixed_key)
        pipe.expire(prefixed_key, expire)
        count, _ = await pipe.execute()
        return count


class InMemoryBackend:
    """Fast in-memory backend for single instance with auto-destroy and self-healing."""
    
    def __init__(self):
        self.store: Dict[str, Tuple[int, float]] = {}
        self._locks_lock = asyncio.Lock()
        self.locks: Dict[str, asyncio.Lock] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
        self._destroyed = False
        self._start_cleanup()

    def _start_cleanup(self):
        """Start or restart cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            return  # Already running
        self._cleanup_task = asyncio.create_task(self._cleanup())

    async def _cleanup(self):
        """Cleanup expired keys every 5 minutes with auto-restart on error."""
        while not self._destroyed:
            try:
                await asyncio.sleep(180)  # 3 minutes
                now = time.time()
                async with self._locks_lock:
                    expired = [k for k, (_, exp) in self.store.items() if exp <= now]
                    for k in expired:
                        self.store.pop(k, None)
                        self.locks.pop(k, None)
            except asyncio.CancelledError:
                break
            except Exception:
                # CRITICAL FIX: Auto-restart on unexpected errors
                if not self._destroyed:
                    await asyncio.sleep(60)  # Back off before restart
                    continue
                break

    async def _get_lock(self, key: str) -> asyncio.Lock:
        """Thread-safe lock retrieval with cleanup task health check."""
        # CRITICAL FIX: Auto-restart cleanup if it died
        if self._cleanup_task and self._cleanup_task.done() and not self._destroyed:
            self._start_cleanup()
        
        # Fast path - lock already exists
        lock = self.locks.get(key)
        if lock:
            return lock
        
        # Slow path - need to create lock
        async with self._locks_lock:
            lock = self.locks.get(key)
            if lock:
                return lock
            lock = asyncio.Lock()
            self.locks[key] = lock
            return lock

    async def incr(self, key: str, limit: int, window: int) -> Tuple[int, int, bool]:
        """Returns (count, reset_timestamp, exceeded)."""
        now = time.time()
        lock = await self._get_lock(key)
        
        async with lock:
            count, expiry = self.store.get(key, (0, 0.0))
            if expiry <= now:
                count = 0
                expiry = now + window
            
            count += 1
            self.store[key] = (count, expiry)
            
            return count, int(expiry), count > limit

    async def ttl(self, key: str) -> int:
        """Get TTL for a key."""
        _, exp = self.store.get(key, (0, 0.0))
        return max(0, int(exp - time.time()))

    async def setex(self, key: str, seconds: int, value: str):
        """Set key with expiry."""
        lock = await self._get_lock(key)
        async with lock:
            self.store[key] = (1, time.time() + seconds)

    async def incr_with_expire(self, key: str, expire: int) -> int:
        """Increment key and set expiry atomically."""
        lock = await self._get_lock(key)
        now = time.time()
        async with lock:
            count, exp = self.store.get(key, (0, 0.0))
            if exp <= now:
                count = 0
            count += 1
            self.store[key] = (count, now + expire)
            return count

    async def destroy(self):
        """Cancel cleanup task and clear state."""
        if self._destroyed:
            return
        self._destroyed = True
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        async with self._locks_lock:
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
        ban_direct: bool = False,
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
        self.rate_page_template = rate_page or RATE_PAGE_TEMPLATE
        # SECURITY FIX: Option to ban unvalidated IPs (direct connections)
        # Set to True if you're not behind a proxy and want to ban direct IPs
        self.ban_direct = ban_direct

    async def _is_banned(self, ip: str) -> Tuple[bool, int]:
        """Check ban status. Returns (is_banned, ttl_seconds)."""
        key = f"ban:{ip}"
        ttl = await self.backend.ttl(key)
        return ttl > 0, max(0, ttl)

    async def _add_offense(self, ip: str, ip_validated: bool):
        """
        Record offense and ban if threshold exceeded.
        
        SECURITY: By default only bans validated IPs (from CF or trusted proxies) to prevent
        ban-DoS via IP spoofing. Set ban_direct=True to also ban direct connections.
        """
        if not self.enable_bans:
            return
        
        # CRITICAL FIX: Configurable ban behavior
        if not ip_validated and not self.ban_direct:
            return
        
        okey = f"offense:{ip}"
        bkey = f"ban:{ip}"

        count = await self.backend.incr_with_expire(okey, self.offense_ttl)
        if count >= self.ban_threshold:
            await self.backend.setex(bkey, self.ban_duration, "1")

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        ip, ip_validated = self.get_ip(scope)
        path = scope["path"]

        # Check ban
        is_banned, ban_ttl = await self._is_banned(ip)
        if is_banned:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            
            # Use safe integer for Retry-After header
            headers = {"Retry-After": str(max(0, min(ban_ttl, 86400)))}  # Cap at 24h
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
            await self._add_offense(ip, ip_validated)
            # Cap retry_after to prevent integer overflow issues
            retry_after = max(0, min(retry_after, 86400))  # Cap at 24 hours
            headers["Retry-After"] = str(retry_after)
            
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            
            accept = next((v.decode("latin-1") for k, v in scope.get("headers", []) 
                          if k.decode("latin-1").lower() == "accept"), "")
            
            if "text/html" in accept or not accept:
                # Safe HTML injection - only integers in controlled template
                safe_page = self.rate_page_template.replace("{retry}", str(retry_after))
                return await HTMLResponse(safe_page, 429, headers)(scope, receive, send)
            
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
