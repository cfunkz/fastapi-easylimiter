"""App served by real uvicorn workers in test_server.py."""

import os

import redis.asyncio as aioredis
from fastapi import FastAPI

from fastapi_easylimiter import RateLimitMiddleware

app = FastAPI()
pool = aioredis.BlockingConnectionPool.from_url(os.environ["REDIS_URL"], max_connections=20, timeout=5)


@app.get("/{path:path}")
async def echo(path: str):
    return {"path": path, "pid": os.getpid()}


app.add_middleware(
    RateLimitMiddleware,
    redis=aioredis.Redis(connection_pool=pool),
    rules={"/*": (1000, 60, "moving"), "/limited": (50, 60, "fixed"), "/sliding": (30, 60, "moving")},
    ban_offenses=int(os.environ.get("BAN_OFFENSES", "0")),
    ban_length="1m",
)
