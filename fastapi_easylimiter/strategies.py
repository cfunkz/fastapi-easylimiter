# strategies.py
import hashlib
from typing import Tuple, Optional
import redis.asyncio as redis


class BaseRedisStrategy:
    """Base class for Redis-backed rate limiting strategies with integrated ban logic."""
    
    def __init__(self, redis_client: redis.Redis, ban_after: int = 8, initial_ban: int = 300, max_ban: int = 86400, site_ban: bool = True):
        self.redis = redis_client
        self.ban_after = ban_after
        self.initial_ban = initial_ban
        self.max_ban = max_ban
        self.site_ban = site_ban

    def _key(self, identifier: str, limit: int, window: int) -> str:
        """Generate consistent key for rate limit and offense tracking."""
        hashed = hashlib.sha256(identifier.encode()).hexdigest()[:16]
        strategy = self.__class__.__name__[:4].lower()
        return f"rl:{strategy}:{hashed}:{limit}:{window}"
    
    def _ban_key(self, identifier: str, limit: Optional[int] = None, window: Optional[int] = None) -> str:
        """Generate ban key - site-wide or per-endpoint based on site_ban setting."""
        hashed = hashlib.sha256(identifier.encode()).hexdigest()[:16]
        if self.site_ban:
            # Site-wide ban: same key for all endpoints
            return f"ban:{hashed}"
        else:
            # Per-endpoint ban: includes limit and window
            strategy = self.__class__.__name__[:4].lower()
            return f"rl:{strategy}:{hashed}:{limit}:{window}:ban"


class FixedWindowStrategy(BaseRedisStrategy):
    """
    Fixed-window rate limiting with atomic ban integration.
    All operations (ban check, rate limit, offense tracking, ban application) in single Lua script.
    """
    
    LUA_SCRIPT = """
    local rl_key = KEYS[1]
    local ban_key = KEYS[2]
    local offense_key = KEYS[3]
    
    local limit = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local ban_after = tonumber(ARGV[3])
    local initial_ban = tonumber(ARGV[4])
    local max_ban = tonumber(ARGV[5])
    
    local now = tonumber(redis.call('TIME')[1])
    local window_start = now - (now % window)
    local window_end = window_start + window
    
    -- STEP 1: Check if banned (atomic check)
    local ban_ttl = redis.call('TTL', ban_key)
    if ban_ttl > 0 then
        return {0, 0, 0, ban_ttl, window_end, now}
    end
    
    -- STEP 2: Check rate limit
    local count = tonumber(redis.call('GET', rl_key) or '0')
    
    if count < limit then
        -- Allow request
        local new_count = redis.call('INCR', rl_key)
        redis.call('EXPIREAT', rl_key, window_end)
        return {1, new_count, limit - new_count, 0, window_end, now}
    else
        -- STEP 3: Rate limit exceeded - record offense atomically
        local offenses = redis.call('INCR', offense_key)
        redis.call('EXPIRE', offense_key, window)
        
        -- STEP 4: Check if ban threshold reached and apply ban atomically
        if offenses >= ban_after then
            local level = offenses - ban_after + 1
            local duration = math.min(initial_ban * (2 ^ (level - 1)), max_ban)
            redis.call('SET', ban_key, '1', 'EX', duration)
            return {0, count, 0, duration, window_end, now}
        end
        
        return {0, count, 0, 0, window_end, now}
    end
    """

    def __init__(self, redis_client: redis.Redis, ban_after: int = 8, initial_ban: int = 300, max_ban: int = 86400, site_ban: bool = True):
        super().__init__(redis_client, ban_after, initial_ban, max_ban, site_ban)
        self.lua = self.redis.register_script(self.LUA_SCRIPT)

    async def hit(self, identifier: str, limit: int, window: int) -> Tuple[bool, int, int, int, int]:
        """
        Returns: (allowed, remaining, reset_time, ban_ttl, now)
        All operations are atomic within single Lua execution.
        """
        rl_key = self._key(identifier, limit, window)
        ban_key = self._ban_key(identifier, limit, window)
        offense_key = f"{rl_key}:off"
        
        result = await self.lua(
            keys=[rl_key, ban_key, offense_key],
            args=[limit, window, self.ban_after, self.initial_ban, self.max_ban]
        )
        
        allowed = result[0] == 1
        remaining = int(result[2])
        reset = int(result[4])
        ban_ttl = int(result[3])
        now = int(result[5])
        
        return allowed, remaining, reset, ban_ttl, now

class MovingWindowStrategy(BaseRedisStrategy):
    """
    Moving window (sliding window counter) with atomic ban integration.
    Uses weighted average of current and previous window counts.
    """
    
    LUA_SCRIPT = """
    local base_key = KEYS[1]
    local ban_key = KEYS[2]
    local offense_key = KEYS[3]
    
    local limit = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local ban_after = tonumber(ARGV[3])
    local initial_ban = tonumber(ARGV[4])
    local max_ban = tonumber(ARGV[5])
    
    local now = tonumber(redis.call('TIME')[1])
    local current_window = math.floor(now / window)
    local prev_window = current_window - 1
    
    local current_key = base_key .. ':' .. current_window
    local prev_key = base_key .. ':' .. prev_window
    local reset = (current_window + 1) * window
    
    -- STEP 1: Check if banned
    local ban_ttl = redis.call('TTL', ban_key)
    if ban_ttl > 0 then
        return {0, 0, 0, ban_ttl, reset, now}
    end
    
    -- STEP 2: Calculate weighted count
    local curr = tonumber(redis.call('GET', current_key) or '0')
    local prev = tonumber(redis.call('GET', prev_key) or '0')
    local elapsed = now % window
    local weight = (window - elapsed) / window
    local weighted_count = math.floor(prev * weight + curr)
    
    if weighted_count < limit then
        -- Allow request
        local new_curr = redis.call('INCR', current_key)
        redis.call('EXPIRE', current_key, window * 2)
        weighted_count = math.floor(prev * weight + new_curr)
        local remaining = limit - weighted_count
        return {1, math.max(0, remaining), reset, 0, reset, now}
    else
        -- STEP 3: Record offense
        local offenses = redis.call('INCR', offense_key)
        redis.call('EXPIRE', offense_key, window * 2)
        
        -- STEP 4: Apply ban if threshold reached
        if offenses >= ban_after then
            local level = offenses - ban_after + 1
            local duration = math.min(initial_ban * (2 ^ (level - 1)), max_ban)
            redis.call('SET', ban_key, '1', 'EX', duration)
            return {0, 0, 0, duration, reset, now}
        end
        
        return {0, 0, reset, 0, reset, now}
    end
    """

    def __init__(self, redis_client: redis.Redis, ban_after: int = 8, initial_ban: int = 300, max_ban: int = 86400, site_ban: bool = True):
        super().__init__(redis_client, ban_after, initial_ban, max_ban, site_ban)
        self.lua = self.redis.register_script(self.LUA_SCRIPT)

    async def hit(self, identifier: str, limit: int, window: int) -> Tuple[bool, int, int, int, int]:
        rl_key = self._key(identifier, limit, window)
        ban_key = self._ban_key(identifier, limit, window)
        offense_key = f"{rl_key}:off"
        
        result = await self.lua(
            keys=[rl_key, ban_key, offense_key],
            args=[limit, window, self.ban_after, self.initial_ban, self.max_ban]
        )
        
        allowed = result[0] == 1
        remaining = int(result[1])
        reset = int(result[4])
        ban_ttl = int(result[3])
        now = int(result[5])
        
        return allowed, remaining, reset, ban_ttl, now