# Changelog

## 1.0.0

A rewrite focused on speed, atomicity and correctness. The `add_middleware(...)` configuration is unchanged.

### Added
- One atomic Lua script per request: ban check, every matching rule, offense counting and ban escalation in a
  single Redis round trip. Quota is consumed only when all matching rules allow the request.
- Concurrent requests are pipelined into one round trip; banned clients are rejected from memory.
- Sliding window counter (`"moving"`) with millisecond precision and exact `Retry-After`.
- IETF `RateLimit` / `RateLimit-Policy` headers.
- `key_func`, `fail_open` and `prefix` options.
- Redis Cluster support.
- After a Redis failure, Redis is skipped for one second so a hung server cannot pile requests up.

### Changed
- Pure ASGI middleware; `redis` is the only dependency (FastAPI/Starlette no longer required).
- `ban_counter_reset` is now `ban_counter_ttl`, matching the README.
- One Redis hash per client (`rl:<identifier>`); keys from 0.x are not read and simply expire.
- Invalid configuration (unknown algorithm, bad duration such as `"1h30m"`) raises `ValueError` at startup.

### Fixed
- With several matching rules, a request rejected by one rule still used quota on the others.
- `"moving"` counted the previous window at full weight for one-second windows.

### Removed
- The `strategies` module.
