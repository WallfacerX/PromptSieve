from contextlib import asynccontextmanager

import httpx
import pytest

from promptsieve.app import create_app
from promptsieve.config import Settings


@pytest.fixture
def settings():
    return Settings(
        _env_file=None, proxy_token="proxy-test-token", openai_api_key="upstream-test-key"
    )


class BytesStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks, self.closed = chunks, False

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        self.closed = True


@asynccontextmanager
async def client_for(settings, handler, detectors=None):
    app = create_app(settings, transport=httpx.MockTransport(handler), detectors=detectors)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://proxy",
            headers={"Authorization": "Bearer proxy-test-token"},
        ) as client:
            yield client


def upstream_json(status=200, body=b'{"id":"mock"}', headers=None):
    return httpx.Response(
        status,
        stream=BytesStream([body]),
        headers={"content-type": "application/json", **(headers or {})},
    )
