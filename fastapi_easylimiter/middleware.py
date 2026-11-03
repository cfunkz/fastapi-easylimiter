"""Pure ASGI rate limiting middleware backed by a single atomic Redis script.

Each client is one small Redis hash holding all of its counters, offenses and
bans. The rules are compiled into a Lua script once, so a request sends only
the client key and the indices of the rules that matched its path. The script
runs three Redis commands (TIME, HMGET, HSET) however many rules match, checks
bans, evaluates every rule, consumes quota only when all of them pass
(all-or-nothing), and records offenses / escalates bans, atomically.

Concurrent requests are pipelined together into one network round trip, and
clients that are already banned are rejected from a small in-process cache
without touching Redis at all.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
import time
from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

from redis.asyncio.cluster import RedisCluster
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import NoScriptError

logger = logging.getLogger("fastapi_easylimiter")

Scope = Dict[str, Any]
Rule = Tuple[int, Union[int, float, str], str]
Duration = Union[int, float, str]

ALGORITHMS = {"fixed": "f", "moving": "m"}

# The generated header defines BAN_AFTER, BAN_MS, BAN_MAX, LEVEL_TTL, KEY_TTL and
#   RULES  = { {limit, window_ms, algo, ban scope, window field, count field, previous field}, ... }
#   SCOPES = { {ban until, offenses, offenses expire, level, level expire}, ... }   (field names)
# KEYS[1] is the client's hash, ARGV the matched rule indices, most specific first.
# Returns {status, index, remaining, ms}
#   0 allowed: index = tightest matched rule, ms = its reset
#   1 limited: index = matched rule to wait for, ms = retry after
#   2 banned:  index = matched ban scope, ms = ban ttl
_CLOCK = """
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
"""
_BODY = """
local k, n = KEYS[1], #ARGV

-- HMGET order: 'x', 5 fields per distinct ban scope, 3 fields per rule.
-- 'x' is the latest moment any escalation level must still be remembered.
local rules, scopes, slot, fields = {}, {}, {}, {'x'}
for a = 1, n do
  local r = RULES[tonumber(ARGV[a])]
  rules[a] = r
  if not slot[r[4]] then
    scopes[#scopes + 1] = SCOPES[r[4]]
    slot[r[4]] = #scopes
  end
end
local ns = #scopes
for s = 1, ns do
  for q = 1, 5 do fields[#fields + 1] = scopes[s][q] end
end
for a = 1, n do
  for q = 5, 7 do fields[#fields + 1] = rules[a][q] end
end
local h = redis.call('HMGET', k, unpack(fields))
local function num(pos) return tonumber(h[pos]) or 0 end

for s = 1, ns do
  local b = num(5 * s - 3)
  if b > now then return {2, s, 0, b - now} end
end

local st, cnt, deny = {}, {}, {}
local wait_max, wait_i = 0, 0
local best, best_r, best_t = 0, 0, 0
for a = 1, n do
  local r, R = rules[a], 1 + 5 * ns + 3 * (a - 1)
  local lim, win = r[1], r[2]
  local w, c = tonumber(h[R + 1]), num(R + 2)
  local left, wait, reset
  if r[3] == 'f' then
    -- fixed window: starts at the client's first hit (w = start ms)
    if w and w <= now and now - w < win then
      st[a], reset = false, w + win - now
    else
      st[a], reset, c = {now, 0}, win, 0
    end
    left = lim - c - 1
    wait = reset
  else
    -- sliding window counter (w = window index): the previous window's count
    -- is weighted by how much of it still overlaps the trailing window
    local cw, p = math.floor(now / win), num(R + 3)
    if w ~= cw then
      if w == cw - 1 then p = c else p = 0 end
      c, st[a] = 0, {cw, p}
    else
      st[a] = false
    end
    local el = now - cw * win
    left = lim - (p * (win - el) / win + c) - 1
    reset = win - el
    if left < 0 then
      if c < lim then
        -- wait for the previous window to decay enough (p > 0 here)
        wait = win - el - (lim - c - 1) * win / p
      else
        -- current window is full: wait for it to become the previous one
        wait = 2 * win - el - (lim - 1) * win / c
      end
    end
  end
  cnt[a] = c
  if left < 0 then
    deny[#deny + 1] = a
    if wait > wait_max then wait_max, wait_i = wait, a end
  elseif best == 0 or left < best_r then
    best, best_r, best_t = a, left, reset
  end
end

local upd, x = {}, num(1)
local function put(pos, v) upd[#upd + 1] = fields[pos]; upd[#upd + 1] = v end

if #deny > 0 then
  if BAN_AFTER == 0 then return {1, wait_i, 0, math.ceil(wait_max) + 1} end
  local seen, ban_s, ban_d = {}, 0, 0
  for _, a in ipairs(deny) do
    local s = slot[rules[a][4]]
    if not seen[s] then
      seen[s] = true
      local o = num(5 * s - 2)
      if num(5 * s - 1) <= now then o = 0 end
      o = o + 1
      if o >= BAN_AFTER then
        local lvl = num(5 * s)
        if num(5 * s + 1) <= now then lvl = 0 end
        lvl = lvl + 1
        local d = math.floor(math.min(BAN_MS * 2 ^ (lvl - 1), BAN_MAX))
        local le = now + d + LEVEL_TTL
        put(5 * s - 3, now + d); put(5 * s - 2, 0); put(5 * s, lvl); put(5 * s + 1, le)
        if le > x then x = le end
        if d > ban_d then ban_s, ban_d = s, d end
      else
        put(5 * s - 2, o); put(5 * s - 1, now + 2 * rules[a][2])
      end
    end
  end
  put(1, x)
  redis.call('HSET', k, unpack(upd))
  redis.call('PEXPIRE', k, math.max(KEY_TTL, x - now))
  if ban_d > 0 then return {2, ban_s, 0, ban_d} end
  return {1, wait_i, 0, math.ceil(wait_max) + 1}
end

local fresh = false
for a = 1, n do
  local R, s = 1 + 5 * ns + 3 * (a - 1), st[a]
  if s then
    put(R + 1, s[1]); put(R + 2, 1); put(R + 3, s[2])
    fresh = true
  else
    put(R + 2, cnt[a] + 1)
  end
end
redis.call('HSET', k, unpack(upd))
-- The expiry only ever moves forward, so it needs refreshing only when a new
-- window starts (at most once per window per rule), not on every hit.
if fresh then redis.call('PEXPIRE', k, math.max(KEY_TTL, x - now)) end
return {0, best, math.floor(best_r), math.ceil(best_t)}
"""

_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "": 1}
_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|)\s*$", re.I)


def parse_duration(value: Duration) -> int:
    """Return milliseconds for 30, 1.5, "500ms", "30s", "5m", "1h" or "1d"."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
    else:
        m = _DURATION.match(str(value))
        if not m:
            raise ValueError(f"invalid duration: {value!r}")
        seconds = float(m.group(1)) * _UNITS[m.group(2).lower()]
    if seconds < 0:
        raise ValueError(f"negative duration: {value!r}")
    return int(round(seconds * 1000))


def _lua_str(s: str) -> str:
    """Quote any string as a Lua literal (non-trivial bytes become \\ddd escapes)."""
    safe = (ch if ch.isascii() and (ch.isalnum() or ch in "/*|_-.~") else _lua_escape(ch) for ch in s)
    return "'" + "".join(safe) + "'"


def _lua_escape(ch: str) -> str:
    return "".join(f"\\{b:03d}" for b in ch.encode())


def _normalize(pattern: str) -> Tuple[str, bool]:
    if not isinstance(pattern, str) or not pattern.startswith("/"):
        raise ValueError(f"path pattern must start with '/': {pattern!r}")
    wildcard = pattern.endswith("/*")
    base = pattern[:-2] if wildcard else pattern
    if "*" in base:
        raise ValueError(f"only a trailing '/*' wildcard is supported: {pattern!r}")
    return base.rstrip("/"), wildcard


class _Rule:
    __slots__ = ("index", "pattern", "name", "limit", "window_ms", "algo", "scope", "policy")

    def __init__(self, index: int, pattern: str, spec: Rule, site_ban: bool):
        try:
            limit, window, algo = spec
        except (TypeError, ValueError):
            raise ValueError(f"rule {pattern!r} must be (limit, window_seconds, 'fixed'|'moving')") from None
        if algo not in ALGORITHMS:
            raise ValueError(f"rule {pattern!r}: unknown algorithm {algo!r}, use 'fixed' or 'moving'")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError(f"rule {pattern!r}: limit must be a positive integer")
        self.window_ms = parse_duration(window)
        if self.window_ms < 1:
            raise ValueError(f"rule {pattern!r}: window must be positive")
        self.index, self.pattern, self.limit, self.algo = index, pattern, limit, ALGORITHMS[algo]
        self.scope = "" if site_ban else pattern
        # RateLimit header policy names are structured-field strings (printable ASCII).
        if all(0x20 <= ord(ch) < 0x7F for ch in pattern):
            self.name = '"' + pattern.replace("\\", "\\\\").replace('"', '\\"') + '"'
        else:
            self.name = f'"rule{index}"'
        self.policy = f"{self.name};q={limit};w={max(1, math.ceil(self.window_ms / 1000))}"

    def lua(self, scope_id: int) -> str:
        fields = ", ".join(_lua_str(self.algo + self.pattern + "|" + f) for f in "wcp")
        return f"{{{self.limit}, {self.window_ms}, '{self.algo}', {scope_id}, {fields}}}"


class _Plan:
    """Everything static about one request path, computed once and cached."""

    __slots__ = ("rules", "scopes", "argv", "policy")

    def __init__(self, rules: List[_Rule]):
        self.rules = rules
        self.scopes: List[str] = []  # distinct ban scopes in the script's order
        for r in rules:
            if r.scope not in self.scopes:
                self.scopes.append(r.scope)
        self.argv = [r.index + 1 for r in rules]
        self.policy = ", ".join(r.policy for r in rules).encode("latin-1")


def _matcher(patterns: Iterable[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    exact: Dict[str, Any] = {}
    prefix: Dict[str, Any] = {}
    for p in patterns:
        base, wildcard = _normalize(p)
        target = prefix if wildcard else exact
        if base in target:
            raise ValueError(f"patterns {target[base]!r} and {p!r} are the same")
        target[base] = p
    return exact, prefix


def _walk(path: str, exact: Dict[str, Any], prefix: Dict[str, Any]) -> List[Any]:
    """Return matches, most specific first: exact match, then '/*' prefixes deepest first."""
    hits = []
    if path in exact:
        hits.append(exact[path])
    while True:
        if path in prefix:
            hits.append(prefix[path])
        if not path:
            return hits
        path = path[: path.rfind("/")]


_PAGE = (
    '<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head>'
    '<body style="margin:0;height:100vh;display:grid;place-items:center;background:#0d1117;'
    'color:#c9d1d9;font:16px system-ui,sans-serif"><div style="max-width:500px;padding:32px;'
    'background:#161b22;border-radius:12px;text-align:center;border:2px solid #30363d">'
    '<h1 style="color:#f85149;margin:0 0 16px;font-size:32px">{title}</h1>'
    '<p style="margin:12px 0">{text}</p><p style="color:#8b949e">Retry in <strong>{retry}</strong>s</p>'
    "</div></body></html>"
)
_ERRORS = {
    429: ("429 Too Many Requests", "Rate limit exceeded.", "rate_limit_exceeded"),
    403: ("403 Blocked", "Temporarily blocked due to abuse.", "forbidden"),
}
_Pending = Tuple[str, List[int], "asyncio.Future[List[int]]"]
_MAX_INFLIGHT = 4  # pipelines in flight at once; requests arriving meanwhile form the next (bigger) batch
_COOLDOWN = 1.0  # after a Redis failure, skip Redis this many seconds instead of queueing behind timeouts


class RateLimitMiddleware:
    """Path-rule rate limiter with escalating bans.

    rules:            {"/api/*": (limit, window_seconds, "fixed" | "moving"), "/exact": (...)}
    exempt:           patterns that are never limited (same syntax as rules)
    ban_offenses:     rejected requests (each within 2 windows of the last) that trigger a ban; 0 disables bans
    ban_length:       first ban; each following ban doubles ...
    ban_max_length:   ... up to this cap
    ban_counter_ttl:  how long the escalation level is remembered after a ban ends
    site_ban:         True bans the client everywhere, False only on the rule that was abused
    key_func:         scope -> identifier (default: client IP); return None to skip limiting
    fail_open:        let requests through when Redis is unreachable (False re-raises)
    prefix:           Redis key prefix
    """

    _clock = _CLOCK  # Lua that sets `now` (ms); tests swap it for a controllable clock

    def __init__(
        self,
        app: Callable,
        redis: Any,
        rules: Dict[str, Rule],
        exempt: Iterable[str] = (),
        ban_offenses: int = 8,
        ban_length: Duration = "5m",
        ban_max_length: Duration = "30m",
        ban_counter_ttl: Duration = "1h",
        site_ban: bool = True,
        key_func: Optional[Callable[[Scope], Optional[str]]] = None,
        fail_open: bool = True,
        prefix: str = "rl",
    ):
        if not rules:
            raise ValueError("at least one rule is required")
        if not isinstance(ban_offenses, int) or isinstance(ban_offenses, bool) or ban_offenses < 0:
            raise ValueError("ban_offenses must be an integer >= 0")
        ban_ms = parse_duration(ban_length)
        if ban_offenses and ban_ms < 1:
            raise ValueError("ban_length must be positive when bans are enabled")
        self.app = app
        self.redis = redis
        self.key_func = key_func
        self.fail_open = fail_open
        self.prefix = prefix

        self._rules = {p: _Rule(i, p, spec, site_ban) for i, (p, spec) in enumerate(rules.items())}
        self._rule_match = _matcher(self._rules)
        self._exempt_match = _matcher(exempt)
        self._plan = lru_cache(maxsize=8192)(self._build_plan)

        # A client's hash lives as long as its longest window (sliding needs two) or ban memory.
        key_ttl = 2 * max(r.window_ms for r in self._rules.values())
        settings = (ban_offenses, ban_ms, max(parse_duration(ban_max_length), ban_ms), parse_duration(ban_counter_ttl))
        scopes = [""] if site_ban else list(self._rules)
        self.script = "\n".join(
            [
                "local BAN_AFTER, BAN_MS, BAN_MAX, LEVEL_TTL, KEY_TTL = " + ", ".join(map(str, (*settings, key_ttl))),
                "local RULES = {",
                *(f"  {r.lua(1 if site_ban else r.index + 1)}," for r in self._rules.values()),
                "}",
                "local SCOPES = {",
                *("  {" + ", ".join(_lua_str(f"{s}|{f}") for f in ("b", "o", "oe", "l", "le")) + "}," for s in scopes),
                "}",
                self._clock,
                _BODY,
            ]
        )
        self._sha = hashlib.sha1(self.script.encode()).hexdigest()

        self._bans: Dict[Tuple[str, str], float] = {}
        self._last_error = 0.0
        self._pending: List[_Pending] = []
        self._scheduled = False
        self._tasks: Set[asyncio.Task] = set()
        self._down_until = 0.0
        self._down_error: Optional[BaseException] = None
        self._cluster_slots: Optional[asyncio.Semaphore] = None

    def _build_plan(self, path: str) -> Optional[_Plan]:
        path = path.rstrip("/")
        if _walk(path, *self._exempt_match):
            return None
        matched = _walk(path, *self._rule_match)
        return _Plan([self._rules[p] for p in matched]) if matched else None

    # -- Redis ------------------------------------------------------------------

    async def _eval(self, key: str, argv: List[int]) -> List[int]:
        """Run the script for one client; calls made in the same event loop tick share a pipeline."""
        if time.monotonic() < self._down_until:
            raise self._unavailable()
        fut = asyncio.get_running_loop().create_future()
        self._pending.append((key, argv, fut))
        self._schedule()
        return await fut

    def _schedule(self) -> None:
        if not self._scheduled:
            self._scheduled = True
            asyncio.get_running_loop().call_soon(self._flush)

    def _flush(self) -> None:
        self._scheduled = False
        if not self._pending or len(self._tasks) >= _MAX_INFLIGHT:
            return  # the next pipeline to finish flushes again
        batch, self._pending = self._pending, []
        if time.monotonic() < self._down_until:
            for _, _, fut in batch:
                if not fut.done():
                    fut.set_exception(self._unavailable())
            return
        task = asyncio.ensure_future(self._send(batch))
        self._tasks.add(task)
        task.add_done_callback(self._sent)

    def _sent(self, task: asyncio.Task) -> None:
        self._tasks.discard(task)
        if self._pending:
            self._schedule()

    def _unavailable(self) -> RedisConnectionError:
        exc = RedisConnectionError(f"redis unavailable, retrying in under {_COOLDOWN:g}s")
        exc.__cause__ = self._down_error
        return exc

    async def _pipeline(self, batch: List[_Pending]) -> List[Any]:
        if isinstance(self.redis, RedisCluster):
            return await self._cluster_calls(batch)
        pipe = self.redis.pipeline(transaction=False)
        for key, argv, _ in batch:
            pipe.evalsha(self._sha, 1, key, *argv)
        return await pipe.execute(raise_on_error=False)

    async def _cluster_calls(self, batch: List[_Pending]) -> List[Any]:
        """Cluster pipelines refuse EVALSHA, so the calls go out concurrently instead."""
        # Learn the slot map before the first burst. A client that discovers it mid-burst gets
        # MOVED replies, and redis-py then drops connections other in-flight calls are using.
        await self.redis.initialize()
        if self._cluster_slots is None:  # stay under the per-node connection limit (100 by default)
            self._cluster_slots = asyncio.Semaphore(50)

        async def call(key: str, argv: List[int]) -> Any:
            async with self._cluster_slots:
                return await self.redis.evalsha(self._sha, 1, key, *argv)

        return list(await asyncio.gather(*(call(k, a) for k, a, _ in batch), return_exceptions=True))

    async def _send(self, batch: List[_Pending]) -> None:
        try:
            results = await self._pipeline(batch)
            retry = [i for i, res in enumerate(results) if isinstance(res, NoScriptError)]
            if retry:  # first use, or Redis restarted / flushed its script cache
                await self.redis.script_load(self.script)
                for i, res in zip(retry, await self._pipeline([batch[i] for i in retry])):
                    results[i] = res
        except Exception as exc:
            self._down_until, self._down_error = time.monotonic() + _COOLDOWN, exc
            for _, _, fut in batch:
                if not fut.done():
                    fut.set_exception(exc)
            return
        for (_, _, fut), res in zip(batch, results):
            if not fut.done():
                if isinstance(res, Exception):
                    fut.set_exception(res)
                else:
                    fut.set_result(res)

    # -- Local ban cache -----------------------------------------------------------

    def _banned_locally(self, ident: str, plan: _Plan) -> int:
        if not self._bans:
            return 0
        now = time.monotonic()
        for scope in plan.scopes:
            until = self._bans.get((ident, scope))
            if until is not None:
                if until > now:
                    return math.ceil((until - now) * 1000)
                del self._bans[(ident, scope)]
        return 0

    def _remember_ban(self, key: Tuple[str, str], ttl_ms: int) -> None:
        bans = self._bans
        if len(bans) >= 100_000:
            now = time.monotonic()
            for k in [k for k, until in bans.items() if until <= now]:
                del bans[k]
            if len(bans) >= 100_000:
                bans.clear()
        bans[key] = time.monotonic() + ttl_ms / 1000

    # -- ASGI -------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Callable, send: Callable) -> None:
        kind = scope["type"]
        if kind != "http" and kind != "websocket":
            return await self.app(scope, receive, send)
        plan = self._plan(scope["path"])
        if plan is None:
            return await self.app(scope, receive, send)
        if self.key_func is not None:
            ident = self.key_func(scope)
            if ident is None:
                return await self.app(scope, receive, send)
        else:
            client = scope.get("client")
            ident = client[0] if client else "unknown"

        ban_ms = self._banned_locally(ident, plan)
        if ban_ms:
            return await self._reject(scope, send, 403, ban_ms, plan, None)

        try:
            status, idx, remaining, ms = await self._eval(f"{self.prefix}:{ident}", plan.argv)
        except Exception:
            now = time.monotonic()
            if now - self._last_error > 10:
                self._last_error = now
                logger.exception("rate limiter: redis call failed (fail_open=%s)", self.fail_open)
            if not self.fail_open:
                raise
            return await self.app(scope, receive, send)

        if status == 2:
            self._remember_ban((ident, plan.scopes[idx - 1]), ms)
            return await self._reject(scope, send, 403, ms, plan, None)
        rule = plan.rules[idx - 1]
        if status == 1:
            return await self._reject(scope, send, 429, ms, plan, rule)
        if kind == "websocket":
            return await self.app(scope, receive, send)

        extra = [
            (b"ratelimit-policy", plan.policy),
            (b"ratelimit", f"{rule.name};r={remaining};t={math.ceil(ms / 1000)}".encode("latin-1")),
        ]

        async def send_with_headers(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [*message.get("headers", ()), *extra]
            await send(message)

        await self.app(scope, receive, send_with_headers)

    async def _reject(
        self, scope: Scope, send: Callable, status: int, ms: int, plan: _Plan, rule: Optional[_Rule]
    ) -> None:
        retry = max(1, math.ceil(ms / 1000))
        title, text, code = _ERRORS[status]
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008, "reason": f"{title}, retry in {retry}s"})
            return
        headers = [(b"retry-after", str(retry).encode())]
        if rule is not None:
            headers += [
                (b"ratelimit-policy", plan.policy),
                (b"ratelimit", f"{rule.name};r=0;t={retry}".encode("latin-1")),
            ]
        accept = next((v for k, v in scope.get("headers", ()) if k == b"accept"), b"")
        if b"text/html" in accept:
            body = _PAGE.format(title=title, text=text, retry=retry).encode()
            ctype = b"text/html; charset=utf-8"
        else:
            body = json.dumps({"error": code, "retry_after": retry}).encode()
            ctype = b"application/json"
        headers += [(b"content-type", ctype), (b"content-length", str(len(body)).encode())]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})
