import hashlib
import redis.asyncio as redis
from typing import Optional, Tuple

class BaseRedisStrategy:
    """Base class for Redis-based rate limiting strategies."""

    def __init__(self, redis_client: redis.Redis, ban_after: int = 8, initial_ban: int = 300, max_ban: int = 86400, ban_counter: int = 3600, site_ban: bool = True):
        self.redis = redis_client
        self.ban_after = ban_after
        self.initial_ban = initial_ban
        self.max_ban = max_ban
        self.ban_counter = ban_counter
        self.site_ban = site_ban

    def _key(self, identifier: str, limit: int, window: int) -> str:
        hashed = hashlib.sha256(identifier.encode()).hexdigest()[:16]
        strategy = self.__class__.__name__[:4].lower()
        return f"rl:{strategy}:{hashed}:{limit}:{window}"

    def _ban_key(self, identifier: str, limit: Optional[int] = None, window: Optional[int] = None) -> str:
        hashed = hashlib.sha256(identifier.encode()).hexdigest()[:16]
        if self.site_ban:
            return f"ban:{hashed}"
        else:
            strategy = self.__class__.__name__[:4].lower()
            return f"rl:{strategy}:{hashed}:{limit}:{window}:ban"

    def _meta_key(self, rl_key: str) -> str:
        """Single meta key to store both offenses and consecutive ban count."""
        return f"{rl_key}:meta"


class FixedWindowStrategy(BaseRedisStrategy):
    """Fixed-window"""

    LUA_SCRIPT = """
    local rl,ban,meta=KEYS[1],KEYS[2],KEYS[3]
    local lim,win,ba,ib,mb,bc_ttl=tonumber(ARGV[1]),tonumber(ARGV[2]),tonumber(ARGV[3]),tonumber(ARGV[4]),tonumber(ARGV[5]),tonumber(ARGV[6])
    local now=tonumber(redis.call('TIME')[1])
    
    -- Calculate window start with integer division for precision
    local ws=now-(now%win)
    local reset=ws+win

    -- Check if banned
    local bt=redis.call('TTL',ban)
    if bt>0 then 
        return {0,0,reset,bt,now+bt}
    end

    -- Get current count
    local c=tonumber(redis.call('GET',rl) or '0')
    
    -- Allow request if under limit
    if c<lim then
        local nc=redis.call('INCR',rl)
        redis.call('EXPIREAT',rl,reset)
        return {1,lim-nc,reset,0,reset}
    end

    -- Rate limit exceeded - track offense
    local o=tonumber(redis.call('HINCRBY',meta,'off',1))
    redis.call('EXPIRE',meta,win*2)

    -- Check if should ban
    if o>=ba then
        local bc=tonumber(redis.call('HINCRBY',meta,'bc',1))
        -- Exponential backoff: initial * 2^(consecutive_bans - 1), capped at max
        local d=math.min(ib*math.pow(2,bc-1),mb)
        redis.call('SET',ban,'1','EX',d)
        redis.call('HSET',meta,'off',0)
        -- Ensure meta persists long enough to track ban counter
        local meta_expire=math.max(d,bc_ttl)
        redis.call('EXPIRE',meta,meta_expire)
        return {0,0,reset,d,now+d}
    end

    -- Rate limited but not banned yet
    return {0,0,reset,0,reset}
    """

    def __init__(self, redis_client: redis.Redis, ban_after: int = 8, initial_ban: int = 300, max_ban: int = 86400, ban_counter: int = 3600, site_ban: bool = True):
        super().__init__(redis_client, ban_after, initial_ban, max_ban, ban_counter, site_ban)
        self.lua = self.redis.register_script(self.LUA_SCRIPT)

    async def hit(self, identifier: str, limit: int, window: int) -> Tuple[bool, int, int, int, int]:
        rl_key = self._key(identifier, limit, window)
        ban_key = self._ban_key(identifier, limit, window)
        meta_key = self._meta_key(rl_key)

        result = await self.lua(
            keys=[rl_key, ban_key, meta_key],
            args=[limit, window, self.ban_after, self.initial_ban, self.max_ban, self.ban_counter]
        )
        # Return: (allowed, remaining, reset_time, ban_ttl, retry_after)
        return result[0]==1, int(result[1]), int(result[2]), int(result[3]), int(result[4])


class MovingWindowStrategy(BaseRedisStrategy):
    """Moving window"""

    LUA_SCRIPT = """
    local base,ban,meta=KEYS[1],KEYS[2],KEYS[3]
    local lim,win,ba,ib,mb,bc_ttl=tonumber(ARGV[1]),tonumber(ARGV[2]),tonumber(ARGV[3]),tonumber(ARGV[4]),tonumber(ARGV[5]),tonumber(ARGV[6])
    local now=tonumber(redis.call('TIME')[1])
    
    -- Calculate current window number and keys
    local cw=math.floor(now/win)
    local ck,pk=base..':'..cw,base..':'..(cw-1)
    local reset=(cw+1)*win

    -- Check if banned
    local bt=redis.call('TTL',ban)
    if bt>0 then 
        return {0,0,reset,bt,now+bt}
    end

    -- Get current and previous window counts
    local curr=tonumber(redis.call('GET',ck) or '0')
    local prev=tonumber(redis.call('GET',pk) or '0')
    
    -- Calculate progress through current window (0.0 to 1.0)
    local progress=(now%win)/win
    
    -- Weighted count: previous window decays linearly, current window grows
    -- This provides smooth rate limiting across window boundaries
    local weighted_count=prev*(1-progress)+curr

    -- Allow request if under limit
    if weighted_count<lim then
        local nc=redis.call('INCR',ck)
        redis.call('EXPIRE',ck,win*2)
        
        -- Recalculate with new current count for accurate remaining
        local new_weighted=prev*(1-progress)+nc
        local remaining=math.max(0,lim-new_weighted)
        
        -- Round remaining down to nearest integer for client display
        remaining=math.floor(remaining)
        
        return {1,remaining,reset,0,reset}
    end

    -- Rate limit exceeded - track offense
    local o=tonumber(redis.call('HINCRBY',meta,'off',1))
    redis.call('EXPIRE',meta,win*2)

    -- Check if should ban
    if o>=ba then
        local bc=tonumber(redis.call('HINCRBY',meta,'bc',1))
        -- Exponential backoff: initial * 2^(consecutive_bans - 1), capped at max
        local d=math.min(ib*math.pow(2,bc-1),mb)
        redis.call('SET',ban,'1','EX',d)
        redis.call('HSET',meta,'off',0)
        -- Ensure meta persists long enough to track ban counter
        local meta_expire=math.max(d,bc_ttl)
        redis.call('EXPIRE',meta,meta_expire)
        return {0,0,reset,d,now+d}
    end

    -- Rate limited but not banned yet
    return {0,0,reset,0,reset}
    """

    def __init__(self, redis_client: redis.Redis, ban_after: int = 8, initial_ban: int = 300, max_ban: int = 86400, ban_counter: int = 3600, site_ban: bool = True):
        super().__init__(redis_client, ban_after, initial_ban, max_ban, ban_counter, site_ban)
        self.lua = self.redis.register_script(self.LUA_SCRIPT)

    async def hit(self, identifier: str, limit: int, window: int) -> Tuple[bool, int, int, int, int]:
        rl_key = self._key(identifier, limit, window)
        ban_key = self._ban_key(identifier, limit, window)
        meta_key = self._meta_key(rl_key)

        result = await self.lua(
            keys=[rl_key, ban_key, meta_key],
            args=[limit, window, self.ban_after, self.initial_ban, self.max_ban, self.ban_counter]
        )
        # Return: (allowed, remaining, reset_time, ban_ttl, retry_after)
        return result[0]==1, int(result[1]), int(result[2]), int(result[3]), int(result[4])