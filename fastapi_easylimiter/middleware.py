# __init__.py
from typing import Dict, Tuple, Optional, List
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.types import ASGIApp, Scope, Receive, Send
import redis.asyncio as redis
from .strategies import FixedWindowStrategy, MovingWindowStrategy

STRATEGY_MAP = {
    "fixed": FixedWindowStrategy,
    "moving": MovingWindowStrategy
}

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
    """ASGI middleware for rate limiting with integrated ban logic."""
    
    def __init__(
        self,
        app: ASGIApp,
        redis: redis.Redis,
        rules: Dict[str, Tuple[int, int, str]],
        exempt: Optional[List[str]] = None,
        ban_offenses: int = 8,
        ban_length: str = "5m",
        ban_max_length: str = "30m",
        ban_counter_reset: str = "1h",
        site_ban: bool = True,
    ):
        self.app = app
        self.redis = redis
        self.ban_after = ban_offenses
        self.initial_ban = parse_duration(ban_length)
        self.max_ban = parse_duration(ban_max_length)
        self.ban_counter = parse_duration(ban_counter_reset)
        self.site_ban = site_ban
        self.rules = self._normalize_rules(rules)
        self.exempt = self._normalize_paths(exempt or [])

    def _get_identifier(self, scope: Scope) -> str:
        return scope["client"][0] if scope.get("client") else "unknown"

    def _normalize_paths(self, paths: List[str]) -> List[Tuple[str, bool]]:
        """Normalize exempt paths for matching."""
        normalized = []
        for p in paths:
            wildcard = p.endswith("/*")
            prefix = p[:-2].rstrip("/") if wildcard else p.rstrip("/")
            normalized.append((prefix, wildcard))
        return normalized

    def _normalize_rules(self, rules: Dict[str, Tuple[int, int, str]]) -> List[Dict]:
        """Normalize and sort rules with strategy instances."""
        normalized = []
        for path, (limit, period, strategy_name) in rules.items():
            if strategy_name.lower() not in STRATEGY_MAP:
                raise ValueError(f"Unknown strategy: {strategy_name}")
            
            wildcard = path.endswith("/*")
            prefix = path[:-2].rstrip("/") if wildcard else path.rstrip("/")
            
            strategy_cls = STRATEGY_MAP[strategy_name.lower()]
            strategy = strategy_cls(
                self.redis,
                ban_after=self.ban_after,
                initial_ban=self.initial_ban,
                max_ban=self.max_ban,
                ban_counter=self.ban_counter,
                site_ban=self.site_ban
            )
            
            normalized.append({
                "prefix": prefix,
                "wildcard": wildcard,
                "limit": int(limit),
                "period": int(period),
                "strategy": strategy,
            })
        
        return sorted(normalized, key=lambda x: (not x["wildcard"], len(x["prefix"]) if x["wildcard"] else -len(x["prefix"])))

    def _matches(self, path: str, pattern: str, wildcard: bool) -> bool:
        """Check if path matches rule pattern."""
        return path.startswith(pattern) if wildcard else path == pattern

    async def _error_response(
        self, scope: Scope, status: int, retry: int, limit: int = 0, period: int = 0
    ) -> Response:
        """Generate error response (HTML or JSON based on Accept header)."""
        headers = {"Retry-After": str(retry)}
        
        if status == 429:
            headers.update({
                "RateLimit-Policy": f"{limit};w={period}",
                "RateLimit": f"limit={limit}, remaining=0, reset={retry}",
            })

        accept = dict(scope.get("headers", [])).get(b"accept", b"").decode()
        
        if "application/json" in accept:
            error_type = "rate_limit_exceeded" if status == 429 else "forbidden"
            return JSONResponse(
                {"error": error_type, "retry_after": retry},
                status_code=status,
                headers=headers
            )
        
        html = ERROR_PAGES[status].format(retry=retry) if status == 429 else ERROR_PAGES[403]
        return HTMLResponse(html, status_code=status, headers=headers)

    async def _websocket_close(self, send: Send, code: int, reason: str) -> None:
        """Close WebSocket connection with reason."""
        reason_bytes = reason.encode('utf-8')
        if len(reason_bytes) > 123:
            reason_bytes = reason_bytes[:120] + b'...'
            reason = reason_bytes.decode('utf-8', errors='ignore')
        
        await send({
            "type": "websocket.close",
            "code": code,
            "reason": reason
        })

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Main middleware handler with atomic ban/rate limit checking."""
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope["path"].rstrip("/")
        
        if any(self._matches(path, prefix, wc) for prefix, wc in self.exempt):
            await self.app(scope, receive, send)
            return

        identifier = self._get_identifier(scope)
        rules_to_apply = [r for r in self.rules if self._matches(path, r["prefix"], r["wildcard"])]
        
        if not rules_to_apply:
            await self.app(scope, receive, send)
            return

        best_remaining = float("inf")
        best_headers = {}
        
        for rule in rules_to_apply:
            allowed, remaining, reset, ban_ttl, now = await rule["strategy"].hit(
                identifier, rule["limit"], rule["period"]
            )
            
            if ban_ttl > 0:
                if scope["type"] == "websocket":
                    await self._websocket_close(send, 1008, f"Banned for {ban_ttl}s")
                    return
                response = await self._error_response(scope, 403, ban_ttl)
                await response(scope, receive, send)
                return
            
            if not allowed:
                retry = max(1, reset - now)
                if scope["type"] == "websocket":
                    await self._websocket_close(send, 1008, f"Rate limited. Retry in {retry}s")
                    return
                response = await self._error_response(scope, 429, retry, rule["limit"], rule["period"])
                await response(scope, receive, send)
                return
            
            if remaining < best_remaining:
                best_remaining = remaining
                retry = max(1, reset - now)
                best_headers = {
                    "RateLimit-Policy": f"{rule['limit']};w={rule['period']}",
                    "RateLimit": f"limit={rule['limit']}, remaining={remaining}, reset={retry}",
                }

        async def send_with_headers(message):
            if message["type"] in ("http.response.start", "websocket.accept") and best_headers:
                headers = list(message.get("headers", []))
                for k, v in best_headers.items():
                    headers.append((k.encode(), v.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)