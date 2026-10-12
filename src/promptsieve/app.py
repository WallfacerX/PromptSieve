import hmac
import json
import logging
import sys
import time
import uuid
from contextlib import asynccontextmanager

import anyio
import httpx
from fastapi import FastAPI, Request
from starlette.requests import ClientDisconnect

from .config import Settings
from .detectors import BaselineDetector
from .inspection import extract, parse_body
from .models import ProxyError
from .policy import decide
from .transport import UpstreamResponse, error_response

LOG = logging.getLogger("promptsieve.audit")
PATHS = {"/v1/responses", "/v1/chat/completions"}


class BoundaryMiddleware:
    def __init__(self, app, settings):
        self.app, self.settings, self.active = app, settings, 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] not in PATHS:
            return await self.app(scope, receive, send)
        started = time.monotonic()
        request_id = uuid.uuid4().hex
        audit = {
            "request_id": request_id,
            "endpoint": scope["path"],
            "mode": self.settings.mode,
            "decision": "reject",
            "detector_ids": [],
            "inspection_ms": 0,
            "outcome": "rejected",
        }
        scope.setdefault("state", {})["audit"] = audit
        acquired = False
        try:
            headers = scope.get("headers", [])
            auth = [v for k, v in headers if k.lower() == b"authorization"]
            expected = ("Bearer " + self.settings.proxy_token.get_secret_value()).encode()
            if len(auth) != 1 or not hmac.compare_digest(auth[0], expected):
                raise ProxyError(401, "unauthorized", "A valid proxy bearer token is required")
            if self.active >= self.settings.max_concurrency:
                raise ProxyError(429, "concurrency_limit", "Proxy concurrency limit reached")
            self.active += 1
            acquired = True
            await self.app(scope, receive, send)
        except ProxyError as exc:
            audit["status"] = exc.status
            await error_response(exc, request_id)(scope, receive, send)
        except ClientDisconnect:
            audit["outcome"] = "client_disconnect"
        except anyio.get_cancelled_exc_class():
            if audit["outcome"] != "client_disconnect":
                audit["outcome"] = "cancelled"
            raise
        finally:
            if acquired:
                self.active -= 1
            audit["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
            LOG.info(json.dumps(audit, separators=(",", ":")))


def create_app(settings: Settings | None = None, transport=None, detectors=None) -> FastAPI:
    settings = settings or Settings()
    detectors = detectors if detectors is not None else [BaselineDetector()]
    if not LOG.handlers:
        LOG.addHandler(logging.StreamHandler(sys.stdout))
    LOG.setLevel(logging.INFO)

    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(settings.read_timeout, connect=settings.connect_timeout),
            limits=httpx.Limits(
                max_connections=settings.max_concurrency,
                max_keepalive_connections=settings.max_concurrency,
            ),
        ) as client:
            app.state.upstream = client
            yield

    app = FastAPI(
        title="PromptSieve", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None
    )
    app.add_middleware(BoundaryMiddleware, settings=settings)

    @app.get("/healthz")
    async def health():
        return {"status": "ok"}

    async def proxy(request: Request):
        audit = request.state.audit
        try:
            if request.url.query:
                raise ProxyError(400, "unsupported_query", "Query parameters are not supported")
            if (
                request.headers.get("content-type", "").split(";")[0].strip().lower()
                != "application/json"
            ):
                raise ProxyError(415, "unsupported_media_type", "Use application/json")
            if request.headers.get("content-encoding", "identity").lower() != "identity":
                raise ProxyError(415, "unsupported_encoding", "Compressed requests are unsupported")
            length = request.headers.get("content-length")
            if length is not None:
                try:
                    size = int(length)
                    if size < 0:
                        raise ValueError
                except ValueError:
                    raise ProxyError(400, "invalid_request", "Invalid content length") from None
                if size > settings.max_request_bytes:
                    raise ProxyError(413, "request_too_large", "Request exceeds byte limit")
            body = bytearray()
            try:
                with anyio.fail_after(settings.body_timeout):
                    async for chunk in request.stream():
                        if len(body) + len(chunk) > settings.max_request_bytes:
                            raise ProxyError(413, "request_too_large", "Request exceeds byte limit")
                        body.extend(chunk)
            except TimeoutError:
                raise ProxyError(408, "body_timeout", "Request body deadline exceeded") from None
            started = time.monotonic()
            data = parse_body(bytes(body))
            segments, gaps = extract(data, request.url.path)
            findings = list(gaps)
            try:
                for segment in segments:
                    for detector in detectors:
                        findings.extend(detector.inspect(segment))
            except Exception:
                raise ProxyError(
                    503, "inspection_failed", "Request inspection could not complete"
                ) from None
            # Bound audit/error output without changing the decision on any finding.
            decision = decide(settings.mode, findings)
            audit.update(
                decision=decision,
                detector_ids=sorted({f.detector_id for f in findings}),
                findings=[f.model_dump() for f in findings[:128]],
                findings_truncated=len(findings) > 128,
                inspection_ms=round((time.monotonic() - started) * 1000, 3),
            )
            if settings.mode == "enforce" and gaps:
                raise ProxyError(
                    422, "unsupported_content", "Request cannot be fully inspected", gaps[:128]
                )
            if decision == "block":
                raise ProxyError(
                    403,
                    "request_blocked",
                    "Request matched prompt-attack heuristics",
                    findings[:128],
                )
            audit["outcome"] = "forwarding"
            return UpstreamResponse(
                request.app.state.upstream,
                settings,
                request.url.path,
                bytes(body),
                audit["request_id"],
                audit,
            )
        except ProxyError as exc:
            audit["status"] = exc.status
            audit["outcome"] = "rejected"
            return error_response(exc, audit["request_id"])

    app.post("/v1/responses")(proxy)
    app.post("/v1/chat/completions")(proxy)
    return app
