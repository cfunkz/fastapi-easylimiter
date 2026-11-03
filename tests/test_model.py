"""Randomized differential test: the Lua script vs. a plain-Python model of the spec.

The script's clock is swapped for a Redis key so time can jump around freely
(milliseconds to hours) while thousands of random requests from a few clients
are compared, response by response, against the model. Independent invariants
are checked on top: no allowed request while banned, never more than `limit`
allowed requests in one fixed window or one sliding-window bucket.
"""

import math
import random
from collections import defaultdict

import pytest

from fastapi_easylimiter import RateLimitMiddleware

RULES = {
    "/*": (20, 60, "moving"),
    "/api/*": (5, 1, "moving"),
    "/api/auth/*": (3, 2, "fixed"),
    "/api/users/me": (1, 5, "fixed"),
}
PATHS = ["/", "/home", "/api", "/api/x", "/api/auth/login", "/api/users/me"]


class Model:
    def __init__(self, mw, ban_after, ban_ms, ban_max, level_ttl, site_ban):
        self.mw = mw
        self.ban_after, self.ban_ms, self.ban_max, self.level_ttl = ban_after, ban_ms, ban_max, level_ttl
        self.site_ban = site_ban
        self.counters = defaultdict(dict)  # (ident, pattern) -> {"w", "c", "p"}
        self.scopes = defaultdict(dict)  # (ident, scope) -> {"b", "o", "oe", "l", "le"}

    def hit(self, ident, path, now):
        plan = self.mw._plan(path)
        rules = plan.rules
        scopes = plan.scopes
        for s_i, scope in enumerate(scopes, 1):
            b = self.scopes[(ident, scope)].get("b", 0)
            if b > now:
                return [2, s_i, 0, b - now]

        new_state, denied = [], []
        best = None  # (left, index, reset)
        wait_max, wait_i = 0, 0
        for a, r in enumerate(rules, 1):
            st = self.counters[(ident, r.pattern)]
            lim, win = r.limit, r.window_ms
            w, c = st.get("w"), st.get("c", 0)
            if r.algo == "f":
                if w is not None and w <= now and now - w < win:
                    new_state.append(None)
                    reset = w + win - now
                else:
                    new_state.append((now, 0))
                    reset, c = win, 0
                left, wait = lim - c - 1, reset
            else:
                cw, p = math.floor(now / win), st.get("p", 0)
                if w != cw:
                    p = c if w == cw - 1 else 0
                    c = 0
                    new_state.append((cw, p))
                else:
                    new_state.append(None)
                el = now - cw * win
                left = lim - (p * (win - el) / win + c) - 1
                reset = win - el
                if left < 0:
                    if c < lim:
                        wait = win - el - (lim - c - 1) * win / p
                    else:
                        wait = 2 * win - el - (lim - 1) * win / c
            if left < 0:
                denied.append(a)
                if wait > wait_max:
                    wait_max, wait_i = wait, a
            elif best is None or left < best[0]:
                best = (left, a, reset)
            new_state[-1] = (new_state[-1], c)

        if denied:
            if self.ban_after == 0:
                return [1, wait_i, 0, math.ceil(wait_max) + 1]
            seen, ban = set(), (0, 0)
            for a in denied:
                scope = rules[a - 1].scope
                if scope in seen:
                    continue
                seen.add(scope)
                sc = self.scopes[(ident, scope)]
                o = sc.get("o", 0) if sc.get("oe", 0) > now else 0
                o += 1
                if o >= self.ban_after:
                    lvl = (sc.get("l", 0) if sc.get("le", 0) > now else 0) + 1
                    d = math.floor(min(self.ban_ms * 2 ** (lvl - 1), self.ban_max))
                    sc.update(b=now + d, o=0, l=lvl, le=now + d + self.level_ttl)
                    if d > ban[1]:
                        ban = (scopes.index(scope) + 1, d)
                else:
                    sc.update(o=o, oe=now + 2 * rules[a - 1].window_ms)
            if ban[1]:
                return [2, ban[0], 0, ban[1]]
            return [1, wait_i, 0, math.ceil(wait_max) + 1]

        for r, (fresh, c) in zip(rules, new_state):
            st = self.counters[(ident, r.pattern)]
            if fresh:
                st.update(w=fresh[0], c=1, p=fresh[1])
            else:
                st["c"] = c + 1
        left, a, reset = best
        return [0, a, math.floor(left), math.ceil(reset)]


def edges(model, now):
    """Upcoming moments where behaviour flips: window ends, ban / offense / level expiry."""
    times = [now]
    for (_, pattern), st in model.counters.items():
        rule = model.mw._rules[pattern]
        if "w" in st:
            start = st["w"] if rule.algo == "f" else st["w"] * rule.window_ms
            times += [start + rule.window_ms, start + 2 * rule.window_ms]
    for sc in model.scopes.values():
        times += [v for k, v in sc.items() if k in ("b", "oe", "le")]
    return [t for t in times if t >= now] or [now]


class FakeClock(RateLimitMiddleware):
    _clock = "local now = tonumber(redis.call('GET', 'test:clock'))"


@pytest.mark.parametrize("site_ban", [True, False])
@pytest.mark.parametrize("ban_after", [0, 4])
async def test_script_matches_model(r, site_ban, ban_after):
    rng = random.Random(f"{site_ban}-{ban_after}")
    mw = FakeClock(
        None,
        redis=r,
        rules=RULES,
        ban_offenses=ban_after,
        ban_length="2s",
        ban_max_length="9s",
        ban_counter_ttl="30s",
        site_ban=site_ban,
    )
    model = Model(mw, ban_after, 2000, 9000, 30000, site_ban)
    now = 1_700_000_000_000 + rng.randrange(60_000)
    allowed = defaultdict(int)  # (ident, pattern, window id) -> allowed count
    banned_until = defaultdict(int)  # (ident, scope) -> ms
    statuses = defaultdict(int)

    for step in range(3000):
        roll = rng.random()
        if roll < 0.15:
            now = rng.choice(edges(model, now)) + rng.choice([-1, 0, 0, 0, 1])  # land exactly on a boundary
        else:
            now += 0 if roll < 0.4 else rng.randrange(1, 300) if roll < 0.97 else rng.randrange(1_000, 90_000)
        ident = rng.choice(["a", "b", "c"])
        path = rng.choice(PATHS)
        await r.set("test:clock", now)

        got = list(await mw._eval(f"rl:{ident}", mw._plan(path).argv))
        want = model.hit(ident, path, now)
        assert got == want, f"step {step}: {ident} {path} at {now}: script {got} != model {want}"
        statuses[got[0]] += 1

        plan = mw._plan(path)
        if got[0] == 0:
            for rule in plan.rules:
                assert banned_until[(ident, rule.scope)] <= now, "allowed while banned"
                st = model.counters[(ident, rule.pattern)]
                bucket = st["w"]  # fixed: window start, moving: window index
                allowed[(ident, rule.pattern, bucket)] += 1
                assert allowed[(ident, rule.pattern, bucket)] <= rule.limit, "limit exceeded in one window"
        elif got[0] == 2:
            banned_until[(ident, plan.scopes[got[1] - 1])] = now + got[3]

    # The random walk must actually exercise every outcome.
    assert statuses[0] > 300 and statuses[1] > 100
    assert (statuses[2] > 5) == (ban_after > 0)


async def test_clock_going_backwards_is_safe(r):
    """A Redis failover to a host whose clock is behind must not lock clients out."""
    mw = FakeClock(None, redis=r, rules={"/*": (2, 10, "fixed")}, ban_offenses=0)
    argv = mw._plan("/").argv
    await r.set("test:clock", 1_000_000)
    assert [(await mw._eval("rl:x", argv))[0] for _ in range(3)] == [0, 0, 1]
    await r.set("test:clock", 1_000_000 - 60_000)  # clock jumps a minute back
    status, _, _, reset = await mw._eval("rl:x", argv)
    assert status == 0 and reset <= 10_000  # treated as a fresh window, never a longer one
