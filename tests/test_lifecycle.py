"""Drive ASGI messages directly so response buffering cannot hide lifecycle bugs."""

import asyncio
import json

import httpx
import pytest
from conftest import BytesStream, upstream_json

from promptsieve.app import create_app


class Exchange:
    def __init__(self, app, body=None, send_hook=None):
        self.app = app
        self.incoming = asyncio.Queue()
        self.outgoing = asyncio.Queue()
        self.send_hook = send_hook
        self.scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/responses",
            "raw_path": b"/v1/responses",
            "query_string": b"",
            "headers": [
                (b"authorization", b"Bearer proxy-test-token"),
                (b"content-type", b"application/json"),
            ],
            "server": ("localhost", 80),
            "client": ("localhost", 5000),
        }
        if body is not None:
            self.feed(body)
        self.task = asyncio.create_task(app(self.scope, self.incoming.get, self.send))

    def feed(self, body, more=False):
        self.incoming.put_nowait({"type": "http.request", "body": body, "more_body": more})

    async def send(self, message):
        if self.send_hook:
            await self.send_hook(message)
        await self.outgoing.put(message)

    async def next(self):
        return await asyncio.wait_for(self.outgoing.get(), 1)

    async def finish(self):
        await asyncio.wait_for(self.task, 1)

    async def disconnect(self):
        self.incoming.put_nowait({"type": "http.disconnect"})
        await self.finish()


BODY = json.dumps({"model": "test", "input": "Hello", "stream": True}).encode()


async def test_full_body_before_forward(settings):
    calls = []
    app = create_app(settings, httpx.MockTransport(lambda r: calls.append(r) or upstream_json()))
    async with app.router.lifespan_context(app):
        exchange = Exchange(app)
        exchange.feed(BODY[:20], more=True)
        await asyncio.sleep(0.01)
        assert not calls
        exchange.feed(BODY[20:])
        await exchange.finish()
        assert len(calls) == 1 and calls[0].content == BODY


async def test_disconnect_before_headers_releases_slot(settings):
    settings.max_concurrency = 1
    entered, cancelled = asyncio.Event(), asyncio.Event()
    calls = []

    async def upstream(request):
        calls.append(request)
        if len(calls) > 1:
            return upstream_json()
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    app = create_app(settings, httpx.MockTransport(upstream))
    async with app.router.lifespan_context(app):
        first = Exchange(app, BODY)
        await asyncio.wait_for(entered.wait(), 1)
        overloaded = Exchange(app, BODY)
        assert (await overloaded.next())["status"] == 429
        await overloaded.finish()
        await first.disconnect()
        assert cancelled.is_set()
        next_request = Exchange(app, BODY)
        assert (await next_request.next())["status"] == 200
        await next_request.finish()


async def test_backpressure_and_disconnect_cleanup(settings):
    read_count = 0
    closed = asyncio.Event()
    sending = asyncio.Event()

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            nonlocal read_count
            for _ in range(10):
                read_count += 1
                yield b"data: hi\n\n"

        async def aclose(self):
            closed.set()

    async def slow_send(message):
        if message["type"] == "http.response.body":
            sending.set()
            await asyncio.Event().wait()

    app = create_app(settings, httpx.MockTransport(lambda r: httpx.Response(200, stream=Stream())))
    async with app.router.lifespan_context(app):
        exchange = Exchange(app, BODY, slow_send)
        await asyncio.wait_for(sending.wait(), 1)
        assert read_count == 1
        await exchange.disconnect()
        assert closed.is_set()


async def test_incremental_delivery(settings):
    release = asyncio.Event()

    class Stream(BytesStream):
        async def __aiter__(self):
            yield b"data: first\n\n"
            await release.wait()
            yield b"data: second\n\n"

    stream = Stream([])
    app = create_app(settings, httpx.MockTransport(lambda r: httpx.Response(200, stream=stream)))
    async with app.router.lifespan_context(app):
        exchange = Exchange(app, BODY)
        assert (await exchange.next())["status"] == 200
        assert (await exchange.next())["body"] == b"data: first\n\n"
        assert not exchange.task.done()
        release.set()
        assert (await exchange.next())["body"] == b"data: second\n\n"
        await exchange.finish()
        assert stream.closed


async def test_total_timeout_and_body_timeout(settings):
    settings.total_timeout = settings.body_timeout = 0.02

    async def upstream(request):
        await asyncio.Event().wait()

    app = create_app(settings, httpx.MockTransport(upstream))
    async with app.router.lifespan_context(app):
        incomplete = Exchange(app)
        assert (await incomplete.next())["status"] == 408
        await incomplete.finish()
        pending = Exchange(app, BODY)
        assert (await pending.next())["status"] == 504
        await pending.finish()


async def test_midstream_error_aborts_without_success(settings):
    class Stream(BytesStream):
        async def __aiter__(self):
            yield b"data: first\n\n"
            raise httpx.ReadTimeout("sensitive upstream detail")

    stream = Stream([])
    app = create_app(settings, httpx.MockTransport(lambda r: httpx.Response(200, stream=stream)))
    async with app.router.lifespan_context(app):
        exchange = Exchange(app, BODY)
        assert (await exchange.next())["status"] == 200
        assert (await exchange.next())["body"] == b"data: first\n\n"
        with pytest.raises(ExceptionGroup) as error:
            await exchange.finish()
        assert "sensitive" not in str(error.value)
        assert exchange.outgoing.empty() and stream.closed


async def test_external_cancellation_closes_stream(settings):
    entered = asyncio.Event()

    class Stream(BytesStream):
        async def __aiter__(self):
            entered.set()
            await asyncio.Event().wait()
            yield b"unreachable"

    stream = Stream([])
    app = create_app(settings, httpx.MockTransport(lambda r: httpx.Response(200, stream=stream)))
    async with app.router.lifespan_context(app):
        exchange = Exchange(app, BODY)
        await asyncio.wait_for(entered.wait(), 1)
        exchange.task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await exchange.finish()
        assert stream.closed
