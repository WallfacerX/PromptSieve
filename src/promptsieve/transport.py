"""Streaming response owns upstream lifetime, including pre-header disconnects."""

import anyio
import httpx
from starlette.responses import JSONResponse, Response

from .models import ProxyError

SAFE_HEADERS = {
    "content-type",
    "content-encoding",
    "content-length",
    "retry-after",
    "x-request-id",
    "openai-processing-ms",
    "openai-version",
}


def error_response(error: ProxyError, request_id: str):
    return JSONResponse(
        {
            "error": {
                "code": error.code,
                "message": error.message,
                "request_id": request_id,
                "findings": [f.model_dump() for f in error.findings],
            }
        },
        status_code=error.status,
        headers={"X-PromptSieve-Request-ID": request_id},
    )


class UpstreamResponse(Response):
    def __init__(self, client, settings, path, body, request_id, audit):
        super().__init__(content=b"")
        self.client, self.settings, self.path, self.body = client, settings, path, body
        self.request_id, self.audit = request_id, audit

    async def __call__(self, scope, receive, send):
        async with anyio.create_task_group() as group:

            async def disconnected():
                while True:
                    if (await receive())["type"] == "http.disconnect":
                        self.audit["outcome"] = "client_disconnect"
                        group.cancel_scope.cancel()
                        return

            async def relay():
                response, started = None, False
                try:
                    with anyio.fail_after(self.settings.total_timeout):
                        request = self.client.build_request(
                            "POST",
                            self.settings.upstream_origin + self.path,
                            content=self.body,
                            headers={
                                "Authorization": "Bearer "
                                + self.settings.openai_api_key.get_secret_value(),
                                "Content-Type": "application/json",
                                "Accept-Encoding": "identity",
                            },
                        )
                        response = await self.client.send(request, stream=True)
                        connection_headers = {
                            name.strip().lower()
                            for name in response.headers.get("connection", "").split(",")
                        }
                        headers = [
                            (k.lower(), v)
                            for k, v in response.headers.raw
                            if (
                                k.decode().lower() in SAFE_HEADERS
                                or k.decode().lower().startswith("x-ratelimit-")
                            )
                            and k.decode().lower() not in connection_headers
                        ]
                        headers.append((b"x-promptsieve-request-id", self.request_id.encode()))
                        self.audit["status"] = response.status_code
                        await send(
                            {
                                "type": "http.response.start",
                                "status": response.status_code,
                                "headers": headers,
                            }
                        )
                        started = True
                        async for chunk in response.aiter_raw():
                            await send(
                                {"type": "http.response.body", "body": chunk, "more_body": True}
                            )
                        await send({"type": "http.response.body", "body": b"", "more_body": False})
                        self.audit["outcome"] = "complete"
                except (httpx.HTTPError, TimeoutError) as exc:
                    timeout = isinstance(exc, (httpx.TimeoutException, TimeoutError))
                    self.audit["outcome"] = "timeout" if timeout else "upstream_error"
                    if not started:
                        status = 504 if timeout else 502
                        self.audit["status"] = status
                        await error_response(
                            ProxyError(
                                status, self.audit["outcome"], "Upstream request could not complete"
                            ),
                            self.request_id,
                        )(scope, receive, send)
                    else:
                        # Raising aborts the connection; do not manufacture a terminal SSE event.
                        raise RuntimeError("Upstream stream interrupted") from None
                finally:
                    if response is not None:
                        with anyio.CancelScope(shield=True):
                            with anyio.move_on_after(2):
                                await response.aclose()
                    group.cancel_scope.cancel()

            group.start_soon(disconnected)
            group.start_soon(relay)
