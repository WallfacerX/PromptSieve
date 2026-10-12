"""Real loopback HTTP tests supplement deterministic ASGI lifecycle tests."""

import asyncio
import socket
from contextlib import asynccontextmanager

import httpx
import uvicorn

from promptsieve.app import create_app


class LoopbackTransport(httpx.AsyncBaseTransport):
    """Test-only mapping; production continues requiring a fixed HTTPS origin."""

    def __init__(self, port):
        self.port = port
        self.inner = httpx.AsyncHTTPTransport(retries=0)

    async def handle_async_request(self, request):
        request.url = request.url.copy_with(scheme="http", host="127.0.0.1", port=self.port)
        return await self.inner.handle_async_request(request)

    async def aclose(self):
        await self.inner.aclose()


@asynccontextmanager
async def servers(settings, handler):
    connections = set()

    async def upstream(reader, writer):
        task = asyncio.current_task()
        connections.add(task)
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            headers = dict(line.split(b":", 1) for line in head.split(b"\r\n")[1:] if b":" in line)
            length = int(headers[b"Content-Length"].strip())
            await reader.readexactly(length)
            await handler(reader, writer)
        finally:
            writer.close()
            await writer.wait_closed()
            connections.discard(task)

    upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
    upstream_port = upstream_server.sockets[0].getsockname()[1]
    app = create_app(settings, transport=LoopbackTransport(upstream_port))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(app, access_log=False, log_level="critical", timeout_graceful_shutdown=1)
    )
    # Avoid changing process-global signal handlers in tests.
    server.install_signal_handlers = lambda: None
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(3):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.005)
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{port}",
            trust_env=False,
            headers={"authorization": "Bearer proxy-test-token"},
        ) as client:
            yield client
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 3)
        sock.close()
        upstream_server.close()
        await upstream_server.wait_closed()
        for connection in list(connections):
            connection.cancel()
        await asyncio.gather(*list(connections), return_exceptions=True)


async def test_network_sse_arrives_before_completion(settings):
    release = asyncio.Event()

    async def handler(reader, writer):
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        for chunk in (b"data: first\n\n", b"data: second\n\n"):
            writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            await writer.drain()
            await release.wait()
        writer.write(b"0\r\n\r\n")
        await writer.drain()

    async with servers(settings, handler) as client:
        async with client.stream(
            "POST", "/v1/responses", json={"model": "test", "input": "Hello", "stream": True}
        ) as response:
            chunks = response.aiter_bytes()
            assert await asyncio.wait_for(anext(chunks), 1) == b"data: first\n\n"
            release.set()
            assert await asyncio.wait_for(anext(chunks), 1) == b"data: second\n\n"


async def test_real_httpx_read_timeout(settings):
    settings.read_timeout = 0.03

    async def handler(reader, writer):
        await reader.read()  # No headers; wait for proxy to close the connection.

    async with servers(settings, handler) as client:
        response = await client.post("/v1/responses", json={"model": "test", "input": "Hello"})
    assert response.status_code == 504
    assert response.json()["error"]["code"] == "timeout"
