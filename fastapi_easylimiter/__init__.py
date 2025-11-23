from typing import Dict, Tuple, Optional, List
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.types import ASGIApp
import redis.asyncio as redis
import time
import hashlib

__version__ = "0.4.1"
__all__ = [
    "RateLimitMiddleware",
    "FixedWindowStrategy",
    "SlidingWindowStrategy",
]


class BaseRedisStrategy:
    """Base class for Redis-backed rate limiting strategies."""

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    def _key(self, identifier: str, limit: int, window: int) -> str:
        """Generate Redis key for identifier with limit/window params."""
        hashed = hashlib.sha256(identifier.encode()).hexdigest()[:16]
        strategy = self.__class__.__name__[:4]
        return f"rl:{strategy}:{hashed}:{limit}:{window}"


class FixedWindowStrategy(BaseRedisStrategy):
    """
    Fixed-window rate limiting: resets counter at fixed time boundaries.
    Simple but can allow bursts at boundaries (up to 2x limit).
    """

    LUA_SCRIPT = """
    local key = KEYS[1]
    local limit = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    
    local window_start = now - (now % window)
    local window_end = window_start + window
    local count = tonumber(redis.call('GET', key) or '0')
    
    if count < limit then
        count = redis.call('INCR', key)
        redis.call('EXPIREAT', key, window_end)
        return {1, count, limit - count, window_end}
    else
        return {0, count, 0, window_end}
    end
    """

    def __init__(self, redis_client: redis.Redis):
        super().__init__(redis_client)
        self.lua_script = self.redis.register_script(self.LUA_SCRIPT)

    async def hit(self, identifier: str, limit: int, window: int) -> Tuple[bool, int]:
        """Check and increment counter. Returns (allowed, reset_timestamp)."""
        key = self._key(identifier, limit, window)
        result = await self.lua_script(keys=[key], args=[limit, window, int(time.time())])
        return result[0] == 1, int(result[3])

    async def get_stats(self, identifier: str, limit: int, window: int) -> Tuple[int, int, int]:
        """Return (count, remaining, reset_timestamp)."""
        key = self._key(identifier, limit, window)
        now = int(time.time())
        window_start = now - (now % window)
        window_end = window_start + window
        
        count = int(await self.redis.get(key) or 0)
        remaining = max(0, limit - count)
        return count, remaining, window_end


class SlidingWindowStrategy(BaseRedisStrategy):
    """
    Sliding window log: tracks timestamp of each request.
    Most accurate but more memory intensive. Prevents boundary bursts.
    """

    LUA_SCRIPT = """
    local key = KEYS[1]
    local limit = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local cutoff = now - window
    
    redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
    local count = redis.call('ZCARD', key)
    
    if count < limit then
        redis.call('ZADD', key, now, now)
        redis.call('EXPIRE', key, window + 10)
        
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        local reset_time = now + window
        if oldest and oldest[2] then
            reset_time = tonumber(oldest[2]) + window
        end
        
        return {1, count + 1, limit - (count + 1), math.floor(reset_time)}
    else
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        local reset_time = now + window
        if oldest and oldest[2] then
            reset_time = tonumber(oldest[2]) + window
        end
        
        return {0, count, 0, math.floor(reset_time)}
    end
    """

    def __init__(self, redis_client: redis.Redis):
        super().__init__(redis_client)
        self.lua_script = self.redis.register_script(self.LUA_SCRIPT)

    async def hit(self, identifier: str, limit: int, window: int) -> Tuple[bool, int]:
        """Check and add request. Returns (allowed, reset_timestamp)."""
        key = self._key(identifier, limit, window)
        result = await self.lua_script(keys=[key], args=[limit, window, time.time()])
        return result[0] == 1, int(result[3])

    async def get_stats(self, identifier: str, limit: int, window: int) -> Tuple[int, int, int]:
        """Return (count, remaining, reset_timestamp)."""
        key = self._key(identifier, limit, window)
        now = time.time()
        cutoff = now - window

        pipe = self.redis.pipeline(transaction=True)
        pipe.zremrangebyscore(key, "-inf", cutoff)
        pipe.zcard(key)
        pipe.zrange(key, 0, 0, withscores=True)
        _, count, oldest_list = await pipe.execute()

        oldest = oldest_list[0][1] if oldest_list else now
        remaining = max(0, limit - count)
        reset = int(oldest + window)
        return count, remaining, reset


STRATEGY_MAP = {
    "fixed": FixedWindowStrategy,
    "sliding": SlidingWindowStrategy,
}


def parse_duration(s: str) -> int:
    """Parse duration string to seconds (e.g., '5m' -> 300, '1h' -> 3600)."""
    if not s:
        return 0
    s = s.strip().lower()
    num = int(''.join(filter(str.isdigit, s)) or "1")
    if "d" in s:
        return num * 86400
    if "h" in s:
        return num * 3600
    if "m" in s:
        return num * 60
    return num


BAN_PAGE = (
    '<body style="margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px system-ui,sans-serif">'
    '<div style="width:500px;padding:32px;background:#161b22;border-radius:12px;text-align:center;border:2px solid #30363d">'
    '<h1 style="color:#f85149;margin:0 0 16px;font-size:32px">403 Blocked</h1>'
    '<p style="margin:12px 0">Too many requests from your IP.</p>'
    '<p style="color:#8b949e">Temporarily blocked due to abuse.</p>'
    '</div></body>'
)

RATE_PAGE = (
    '<body style="margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;color:#c9d1d9;font:16px system-ui,sans-serif">'
    '<div style="width:500px;padding:32px;background:#161b22;border-radius:12px;text-align:center;border:2px solid #30363d">'
    '<h1 style="color:#f85149;margin:0 0 16px;font-size:32px">429 Too Many Requests</h1>'
    '<p style="margin:12px 0">Rate limit exceeded.</p>'
    '<p style="color:#8b949e">Retry in <strong>{retry}</strong>s</p>'
    '</div></body>'
)


class RateLimitMiddleware(BaseHTTPMiddleware):
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
    ):
        super().__init__(app)
        self.redis = redis
        self.rules = self._normalize_rules(rules)
        self.exempt = self._normalize_paths(exempt or [])
        self.enable_bans = enable_bans
        self.ban_after_offenses = ban_offenses
        self.ban_window_sec = parse_duration(ban_window)
        self.initial_ban_sec = parse_duration(ban_length)
        self.max_ban_sec = parse_duration(ban_max_length)

    def _hash_identifier(self, identifier: str) -> str:
        """Hash identifier for consistent Redis keys."""
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]

    def _normalize_paths(self, paths: List[str]) -> List[Dict]:
        """Normalize paths for matching (handles wildcards)."""
        normalized = []
        for path in paths:
            wildcard = path.endswith("/*")
            prefix = path[:-2].rstrip("/") if wildcard else path.rstrip("/")
            normalized.append({"prefix": prefix, "wildcard": wildcard})
        return normalized

    def _normalize_rules(self, rules: Dict[str, Tuple[int, int, str]]) -> List[Dict]:
        """Normalize and sort rules for hierarchical matching."""
        normalized = []
        
        for path, (limit, period, strategy_name) in rules.items():
            if strategy_name.lower() not in STRATEGY_MAP:
                raise ValueError(f"Unknown strategy: {strategy_name}")
            
            strategy_cls = STRATEGY_MAP[strategy_name.lower()]
            wildcard = path.endswith("/*")
            prefix = path[:-2].rstrip("/") if wildcard else path.rstrip("/")
            
            normalized.append({
                "prefix": prefix,
                "wildcard": wildcard,
                "limit": int(limit),
                "period": int(period),
                "strategy_cls": strategy_cls,
            })
        
        # Sort: wildcards first (shortest first), then exact matches (longest first)
        return sorted(
            normalized,
            key=lambda x: (not x["wildcard"], len(x["prefix"]) if x["wildcard"] else -len(x["prefix"]))
        )

    def _get_identifier(self, request: Request) -> str:
        """Get client identifier for rate limiting."""
        return request.client.host if request.client else "unknown"

    def _is_exempt(self, path: str) -> bool:
        """Check if path is exempt from rate limiting."""
        path = path.rstrip("/")
        for exempt in self.exempt:
            if exempt["wildcard"]:
                if path.startswith(exempt["prefix"]):
                    return True
            elif path == exempt["prefix"]:
                return True
        return False

    def _get_matching_rules(self, path: str) -> List[Dict]:
        """Get all rules matching this path in hierarchical order."""
        path = path.rstrip("/")
        matches = []
        for rule in self.rules:
            if rule["wildcard"]:
                if path.startswith(rule["prefix"]):
                    matches.append(rule)
            elif path == rule["prefix"]:
                matches.append(rule)
        return matches

    def _is_json_requested(self, request: Request) -> bool:
        """Check if client expects JSON response."""
        accept = request.headers.get("accept", "")
        ua = request.headers.get("user-agent", "").lower()
        return ("application/json" in accept or "text/json" in accept or
                any(x in ua for x in ["curl", "wget", "postman", "insomnia", "httpie", "python-requests"]))

    def _error_response(
        self, 
        request: Request, 
        status_code: int, 
        retry_after: int,
        message: str, 
        limit: int = 0, 
        period: int = 0
    ) -> Response:
        """Generate error response (HTML or JSON based on request)."""
        headers = {"Retry-After": str(retry_after)}

        if status_code == 429:
            headers.update({
                "RateLimit-Policy": f"{limit};w={period}",
                "RateLimit": f"limit={limit}, remaining=0, reset={retry_after}",
            })

        if self._is_json_requested(request):
            data = {
                "error": "rate_limit_exceeded" if status_code == 429 else "forbidden",
                "detail": message,
                "retry_after": retry_after
            }
            return JSONResponse(data, status_code=status_code, headers=headers)

        html = RATE_PAGE.format(retry=retry_after) if status_code == 429 else BAN_PAGE
        return HTMLResponse(html, status_code=status_code, headers=headers)

    async def _check_ban(self, identifier: str) -> Optional[int]:
        """Check if identifier is banned. Returns TTL if banned, None otherwise."""
        hashed = self._hash_identifier(identifier)
        ban_key = f"ban:{hashed}"
        if await self.redis.get(ban_key):
            return await self.redis.ttl(ban_key)
        return None

    async def _record_offense(self, identifier: str) -> Optional[int]:
        """Record rate limit offense. Returns ban duration if threshold exceeded, None otherwise."""
        hashed = self._hash_identifier(identifier)
        offense_key = f"offense:{hashed}"
        now = int(time.time())
        
        await self.redis.zadd(offense_key, {str(now): now})
        await self.redis.zremrangebyscore(offense_key, 0, now - self.ban_window_sec)
        await self.redis.expire(offense_key, self.ban_window_sec + 60)
        
        offense_count = await self.redis.zcard(offense_key)
        
        if offense_count >= self.ban_after_offenses:
            level = offense_count - self.ban_after_offenses + 1
            ban_duration = min(self.initial_ban_sec * (2 ** (level - 1)), self.max_ban_sec)
            await self.redis.setex(f"ban:{hashed}", int(ban_duration), "1")
            return int(ban_duration)
        
        return None

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path.rstrip("/")
        
        if self._is_exempt(path):
            return await call_next(request)

        identifier = self._get_identifier(request)

        # Check for active ban
        if self.enable_bans:
            ban_ttl = await self._check_ban(identifier)
            if ban_ttl:
                return self._error_response(request, 403, ban_ttl, "Access blocked due to repeated abuse")

        rules_to_apply = self._get_matching_rules(path)
        if not rules_to_apply:
            return await call_next(request)

        # Check all matching rules
        allowed_rules = []
        for rule in rules_to_apply:
            strategy = rule["strategy_cls"](self.redis)
            allowed, reset_ts = await strategy.hit(identifier, rule["limit"], rule["period"])
            
            if not allowed:
                reset_seconds = max(1, int(reset_ts - time.time()))
                
                # Record offense and check for ban
                if self.enable_bans:
                    ban_duration = await self._record_offense(identifier)
                    if ban_duration:
                        return self._error_response(
                            request, 403, ban_duration, 
                            f"Banned for {ban_duration // 60} minutes due to abuse"
                        )
                
                return self._error_response(
                    request, 429, reset_seconds, "Rate limit exceeded",
                    rule["limit"], rule["period"]
                )
            
            allowed_rules.append(rule)

        # Add rate limit headers from most restrictive rule
        response = await call_next(request)
        
        if allowed_rules:
            best_remaining = float("inf")
            best_headers = {}
            
            for rule in allowed_rules:
                strategy = rule["strategy_cls"](self.redis)
                _, remaining, reset_ts = await strategy.get_stats(identifier, rule["limit"], rule["period"])
                
                if remaining < best_remaining:
                    best_remaining = remaining
                    reset_seconds = max(1, int(reset_ts - time.time()))
                    best_headers = {
                        "RateLimit-Policy": f"{rule['limit']};w={rule['period']}",
                        "RateLimit": f"limit={rule['limit']}, remaining={remaining}, reset={reset_seconds}",
                    }
            
            for k, v in best_headers.items():
                response.headers[k] = v

        return response