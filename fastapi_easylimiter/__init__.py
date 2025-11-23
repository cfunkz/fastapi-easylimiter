from typing import Dict, Tuple, Optional, List
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.types import ASGIApp, Scope, Receive, Send
import redis.asyncio as redis
import hashlib
from .strategies import FixedWindowStrategy, SlidingWindowStrategy, MovingWindowStrategy

__version__ = "0.4.2"
__all__ = ["RateLimitMiddleware", "FixedWindowStrategy", "SlidingWindowStrategy", "MovingWindowStrategy"]

STRATEGY_MAP = {"fixed": FixedWindowStrategy, "sliding": SlidingWindowStrategy, "moving": MovingWindowStrategy}

def parse_duration(s: str) -> int:
    """Parse duration string to seconds (e.g., '5m' -> 300)."""
    if not s:
        return 0
    s = s.strip().lower()
    num = int(''.join(filter(str.isdigit, s)) or "1")
    return num * (86400 if "d" in s else 3600 if "h" in s else 60 if "m" in s else 1)


ERROR_PAGES = {
    429: '<body style="margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px system-ui,sans-serif">'
         '<div style="width:500px;padding:32px;background:#161b22;border-radius:12px;text-align:center;border:2px solid #30363d">'
         '<h1 style="color:#f85149;margin:0 0 16px;font-size:32px">429 Too Many Requests</h1>'
         '<p style="margin:12px 0">Rate limit exceeded.</p>'
         '<p style="color:#8b949e">Retry in <strong>{retry}</strong>s</p></div></body>',
    403: '<body style="margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px system-ui,sans-serif">'
         '<div style="width:500px;padding:32px;background:#161b22;border-radius:12px;text-align:center;border:2px solid#30363d">'
         '<h1 style="color:#f85149;margin:0 0 16px;font-size:32px">403 Blocked</h1>'
         '<p style="margin:12px 0">Too many requests from your IP.</p>'
         '<p style="color:#8b949e">Temporarily blocked due to abuse.</p></div></body>'
}


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        redis: redis.Redis,
        rules: Dict[str, Tuple[int, int, str]],
        exempt: Optional[List[str]] = None,
        enable_bans: bool = True,
        ban_offenses: int = 10,
        ban_window: str = "10m",
        ban_length: str = "5m",
        ban_max_length: str = "1d",
        trust_xff: bool = False,
    ):
        self.app = app
        self.redis = redis
        self.rules = self._normalize_rules(rules)
        self.exempt = self._normalize_paths(exempt or [])
        self.enable_bans = enable_bans
        self.ban_after = ban_offenses
        self.ban_window = parse_duration(ban_window)
        self.initial_ban = parse_duration(ban_length)
        self.max_ban = parse_duration(ban_max_length)
        self.trust_xff = trust_xff

    def _get_identifier(self, scope: Scope) -> str:
        """
        Extract client identifier for rate limiting.
        
        If trust_xff=True, uses X-Forwarded-For header (first IP in chain).
        WARNING: Only enable trust_xff behind a trusted reverse proxy that
        properly sets/strips X-Forwarded-For headers. Untrusted XFF allows
        trivial rate limit bypass via header spoofing.
        """
        if self.trust_xff:
            headers_dict = dict(scope.get("headers", []))
            xff = headers_dict.get(b"x-forwarded-for", b"").decode().strip()
            if xff:
                # Take first IP in chain (client IP before any proxies)
                client_ip = xff.split(",")[0].strip()
                if client_ip:
                    return client_ip
        
        # Fallback to direct connection IP
        return scope["client"][0] if scope.get("client") else "unknown"

    def _normalize_paths(self, paths: List[str]) -> List[Tuple[str, bool]]:
        return [(p[:-2].rstrip("/") if p.endswith("/*") else p.rstrip("/"), p.endswith("/*")) for p in paths]

    def _normalize_rules(self, rules: Dict[str, Tuple[int, int, str]]) -> List[Dict]:
        normalized = []
        for path, (limit, period, strategy_name) in rules.items():
            if strategy_name.lower() not in STRATEGY_MAP:
                raise ValueError(f"Unknown strategy: {strategy_name}")
            
            wildcard = path.endswith("/*")
            prefix = path[:-2].rstrip("/") if wildcard else path.rstrip("/")
            
            normalized.append({
                "prefix": prefix,
                "wildcard": wildcard,
                "limit": int(limit),
                "period": int(period),
                "strategy_cls": STRATEGY_MAP[strategy_name.lower()],
            })
        
        return sorted(normalized, key=lambda x: (not x["wildcard"], len(x["prefix"]) if x["wildcard"] else -len(x["prefix"])))

    def _matches(self, path: str, pattern: str, wildcard: bool) -> bool:
        return path.startswith(pattern) if wildcard else path == pattern

    def _hash(self, identifier: str) -> str:
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]

    async def _check_ban(self, identifier: str) -> Optional[int]:
        ban_key = f"ban:{self._hash(identifier)}"
        if await self.redis.get(ban_key):
            return await self.redis.ttl(ban_key)
        return None

    async def _record_offense(self, identifier: str) -> Optional[int]:
        hashed = self._hash(identifier)
        offense_key = f"offense:{hashed}"
        
        # Get current Redis time for consistency
        redis_time = await self.redis.time()
        now = int(redis_time[0])
        
        pipe = self.redis.pipeline(transaction=False)
        pipe.zadd(offense_key, {str(now): now})
        pipe.zremrangebyscore(offense_key, 0, now - self.ban_window)
        pipe.expire(offense_key, self.ban_window + 60)
        pipe.zcard(offense_key)
        results = await pipe.execute()
        
        offense_count = results[3]  # Get count from pipeline result
        
        if offense_count >= self.ban_after:
            level = offense_count - self.ban_after + 1
            ban_duration = min(self.initial_ban * (2 ** (level - 1)), self.max_ban)
            await self.redis.setex(f"ban:{hashed}", int(ban_duration), "1")
            return int(ban_duration)
        return None

    async def _error_response(self, scope: Scope, status: int, retry: int, msg: str, limit: int = 0, period: int = 0) -> Response:
        headers = {"Retry-After": str(retry)}
        
        if status == 429:
            headers.update({
                "RateLimit-Policy": f"{limit};w={period}",
                "RateLimit": f"limit={limit}, remaining=0, reset={retry}",
            })

        accept = dict(scope.get("headers", [])).get(b"accept", b"").decode()
        ua = dict(scope.get("headers", [])).get(b"user-agent", b"").decode().lower()
        
        if "application/json" in accept or any(x in ua for x in ["curl", "wget", "postman", "python-requests"]):
            return JSONResponse(
                {"error": "rate_limit_exceeded" if status == 429 else "forbidden", "detail": msg, "retry_after": retry},
                status_code=status,
                headers=headers
            )
        
        html = ERROR_PAGES[status].format(retry=retry) if status == 429 else ERROR_PAGES[403]
        return HTMLResponse(html, status_code=status, headers=headers)

    async def _websocket_close(self, send: Send, code: int, reason: str) -> None:
        """Send WebSocket close frame and disconnect."""
        await send({
            "type": "websocket.close",
            "code": code,
            "reason": reason[:123]  # Max 123 bytes for close reason
        })

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope["path"].rstrip("/")
        
        # Fast path: exempt routes
        if any(self._matches(path, prefix, wc) for prefix, wc in self.exempt):
            await self.app(scope, receive, send)
            return

        identifier = self._get_identifier(scope)

        # Check ban
        if self.enable_bans:
            ban_ttl = await self._check_ban(identifier)
            if ban_ttl:
                if scope["type"] == "websocket":
                    await self._websocket_close(send, 1008, "Banned: Access blocked due to abuse")
                    return
                response = await self._error_response(scope, 403, ban_ttl, "Access blocked due to repeated abuse")
                await response(scope, receive, send)
                return

        # Get matching rules
        rules_to_apply = [r for r in self.rules if self._matches(path, r["prefix"], r["wildcard"])]
        
        if not rules_to_apply:
            await self.app(scope, receive, send)
            return

        # Check all rules
        best_remaining = float("inf")
        best_headers = {}
        
        # Get Redis time once for all calculations
        redis_time = await self.redis.time()
        now = int(redis_time[0])
        
        for rule in rules_to_apply:
            strategy = rule["strategy_cls"](self.redis)
            allowed, remaining, reset_ts = await strategy.hit(identifier, rule["limit"], rule["period"])
            
            if not allowed:
                reset_seconds = max(1, int(reset_ts - now))
                
                if self.enable_bans:
                    ban_duration = await self._record_offense(identifier)
                    if ban_duration:
                        if scope["type"] == "websocket":
                            await self._websocket_close(send, 1008, f"Banned: {ban_duration // 60}m abuse")
                            return
                        response = await self._error_response(scope, 403, ban_duration, f"Banned for {ban_duration // 60} minutes")
                        await response(scope, receive, send)
                        return
                
                if scope["type"] == "websocket":
                    await self._websocket_close(send, 1008, f"Rate limited: retry in {reset_seconds}s")
                    return
                    
                response = await self._error_response(scope, 429, reset_seconds, "Rate limit exceeded", rule["limit"], rule["period"])
                await response(scope, receive, send)
                return
            
            if remaining < best_remaining:
                best_remaining = remaining
                reset_seconds = max(1, int(reset_ts - now))
                best_headers = {
                    "RateLimit-Policy": f"{rule['limit']};w={rule['period']}",
                    "RateLimit": f"limit={rule['limit']}, remaining={remaining}, reset={reset_seconds}",
                }

        # WebSocket: pass through (headers added during handshake only)
        if scope["type"] == "websocket":
            # Add headers to handshake response
            async def send_with_headers(message):
                if message["type"] == "websocket.accept" and best_headers:
                    headers = list(message.get("headers", []))
                    for k, v in best_headers.items():
                        headers.append((k.encode(), v.encode()))
                    message["headers"] = headers
                await send(message)
            
            await self.app(scope, receive, send_with_headers)
            return

        # HTTP: pass through and add headers
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                for k, v in best_headers.items():
                    headers.append((k.encode(), v.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)