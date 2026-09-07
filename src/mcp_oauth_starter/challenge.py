"""Add the `scope` parameter to WWW-Authenticate challenges.

MCP 2026-07-28, *Scope Selection Strategy*:

    MCP servers SHOULD include a `scope` parameter in the `WWW-Authenticate`
    header as defined in RFC 6750 Section 3 to indicate the scopes required
    for accessing the resource.

The SDK's bearer middleware emits `error`, `error_description` and
`resource_metadata` but not `scope`, so a client following the documented
priority order falls back to `scopes_supported` from the metadata document —
an extra round trip on every cold start. This middleware appends the scopes
to the challenge so the client can skip that fetch.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

_HEADER = b"www-authenticate"


class ScopeChallengeMiddleware:
    """ASGI middleware that appends `scope="..."` to Bearer challenges."""

    def __init__(self, app: Any, scopes: list[str]) -> None:
        self.app = app
        self._param = b'scope="' + " ".join(scopes).encode("ascii") + b'"'
        self._enabled = bool(scopes)

    async def __call__(self, scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        if not self._enabled or scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: MutableMapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                message["headers"] = [
                    (k, self._augment(v)) if k.lower() == _HEADER else (k, v)
                    for k, v in message.get("headers", [])
                ]
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _augment(self, value: bytes) -> bytes:
        if b"scope=" in value or not value.lower().startswith(b"bearer"):
            return value
        return value + b", " + self._param
