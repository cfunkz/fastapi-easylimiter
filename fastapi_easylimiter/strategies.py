# strategies.py
import hashlib
from typing import Tuple
import redis.asyncio as redis

class BaseRedisStrategy:
    """Base class for Redis-backed rate limiting strategies."""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    def _key(self, identifier: str, limit: int, window: int) -> str:
        hashed = hashlib.sha256(identifier.encode()).hexdigest()[:16]
        strategy = self.__class__.__name__[:4]
        return f"rl:{strategy}:{hashed}:{limit}:{window}"


class FixedWindowStrategy(BaseRedisStrategy):
    """Fixed-window rate limiting: resets counter at fixed time boundaries."""
    
    LUA_SCRIPT = """
    local key, limit, window = KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[2])
    local now = tonumber(redis.call('TIME')[1])
    local window_start = now - (now % window)
    local window_end = window_start + window
    local count = tonumber(redis.call('GET', key) or '0')
    
    if count < limit then
        count = redis.call('INCR', key)
        redis.call('EXPIREAT', key, window_end)
        return {1, count, limit - count, window_end, now}
    end
    return {0, count, 0, window_end, now}
    """

    def __init__(self, redis_client: redis.Redis):
        super().__init__(redis_client)
        self.lua_script = self.redis.register_script(self.LUA_SCRIPT)

    async def hit(self, identifier: str, limit: int, window: int) -> Tuple[bool, int, int, int]:
        key = self._key(identifier, limit, window)
        result = await self.lua_script(keys=[key], args=[limit, window])
        return result[0] == 1, int(result[2]), int(result[3]), int(result[4])


class SlidingWindowStrategy(BaseRedisStrategy):
    """Sliding window log: tracks timestamp of each request."""
    
    LUA_SCRIPT = """
    local key, limit, window = KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[2])
    local now = tonumber(redis.call('TIME')[1])
    local cutoff = now - window
    
    redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
    local count = redis.call('ZCARD', key)
    
    if count < limit then
        redis.call('ZADD', key, now, now)
        redis.call('EXPIRE', key, window + 10)
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        local reset = oldest[2] and tonumber(oldest[2]) + window or now + window
        return {1, limit - count - 1, math.floor(reset), now}
    end
    
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local reset = oldest[2] and tonumber(oldest[2]) + window or now + window
    return {0, 0, math.floor(reset), now}
    """

    def __init__(self, redis_client: redis.Redis):
        super().__init__(redis_client)
        self.lua_script = self.redis.register_script(self.LUA_SCRIPT)

    async def hit(self, identifier: str, limit: int, window: int) -> Tuple[bool, int, int, int]:
        key = self._key(identifier, limit, window)
        result = await self.lua_script(keys=[key], args=[limit, window])
        return result[0] == 1, int(result[1]), int(result[2]), int(result[3])


class MovingWindowStrategy(BaseRedisStrategy):
    """
    Moving window (sliding window counter): combines fixed windows with weighted averaging.
    More memory efficient than sliding log, more accurate than fixed window.
    Uses current + previous window counts with time-based weighting.
    """
    
    LUA_SCRIPT = """
    local key, limit, window = KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[2])
    local now = tonumber(redis.call('TIME')[1])
    local current_window = math.floor(now / window)
    local previous_window = current_window - 1
    
    local current_key = key .. ':' .. current_window
    local previous_key = key .. ':' .. previous_window
    
    -- Get counts from both windows
    local current_count = tonumber(redis.call('GET', current_key) or '0')
    local previous_count = tonumber(redis.call('GET', previous_key) or '0')
    
    -- Calculate weight for previous window (how much of it overlaps with current period)
    local elapsed_in_current = now % window
    local weight = (window - elapsed_in_current) / window
    
    -- Weighted count: previous * weight + current
    local weighted_count = math.floor(previous_count * weight + current_count)
    
    if weighted_count < limit then
        -- Increment current window
        local new_count = redis.call('INCR', current_key)
        redis.call('EXPIRE', current_key, window * 2)
        
        -- Recalculate with new count
        weighted_count = math.floor(previous_count * weight + new_count)
        local remaining = limit - weighted_count
        local reset = (current_window + 1) * window
        
        return {1, math.max(0, remaining), reset, now}
    end
    
    local reset = (current_window + 1) * window
    return {0, 0, reset, now}
    """

    def __init__(self, redis_client: redis.Redis):
        super().__init__(redis_client)
        self.lua_script = self.redis.register_script(self.LUA_SCRIPT)

    async def hit(self, identifier: str, limit: int, window: int) -> Tuple[bool, int, int, int]:
        key = self._key(identifier, limit, window)
        result = await self.lua_script(keys=[key], args=[limit, window])
        return result[0] == 1, int(result[1]), int(result[2]), int(result[3])