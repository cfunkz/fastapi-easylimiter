import os
import shutil
import socket
import subprocess
import tempfile
import time

import pytest
import pytest_asyncio
import redis.asyncio as aioredis


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def spawn_redis(port: int, *args: str, cwd=None) -> subprocess.Popen:
    """Start a throwaway redis-server on `port` and wait until it accepts connections."""
    binary = shutil.which("redis-server")
    if not binary:
        pytest.skip("redis-server is not installed")
    proc = subprocess.Popen(
        [binary, "--port", str(port), "--save", "", "--appendonly", "no", *args],
        stdout=subprocess.DEVNULL,
        cwd=cwd or tempfile.mkdtemp(),
    )
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close()
            return proc
        except OSError:
            time.sleep(0.05)
    proc.kill()
    raise RuntimeError("redis-server did not start")


@pytest.fixture(scope="session")
def redis_url():
    """Use $REDIS_URL, or start a throwaway redis-server for the test session."""
    url = os.environ.get("REDIS_URL")
    if url:
        yield url
        return
    port = free_port()
    proc = spawn_redis(port)
    yield f"redis://127.0.0.1:{port}/15"
    proc.terminate()
    proc.wait()


@pytest_asyncio.fixture
async def r(redis_url):
    # A blocking pool waits for a free connection instead of erroring under bursts.
    client = aioredis.Redis(connection_pool=aioredis.BlockingConnectionPool.from_url(redis_url, max_connections=50))
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()
