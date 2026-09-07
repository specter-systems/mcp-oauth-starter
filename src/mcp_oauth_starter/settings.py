"""Configuration, read once from the environment.

Every value here has a spec meaning. `RESOURCE_URL` in particular is the
canonical URI of this server as defined in RFC 8707 §2 and used by MCP
clients as the OAuth `resource` parameter, so it must match byte-for-byte
what clients send: https scheme, no fragment, no trailing slash.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(
            f"{name} is not set. Copy .env.example to .env and fill it in."
        )
    return value


def _scopes(raw: str) -> list[str]:
    return [s for s in raw.replace(",", " ").split() if s]


@dataclass(frozen=True)
class Settings:
    """Resolved server configuration."""

    resource_url: str
    """Canonical URI of this MCP server (RFC 8707 §2). No trailing slash."""

    issuer_url: str
    """Issuer identifier of the authorization server that mints our tokens."""

    jwks_url: str
    """JWKS endpoint used to verify access-token signatures."""

    required_scopes: list[str] = field(default_factory=list)
    """Minimum scopes advertised in `scopes_supported` and the 401 challenge."""

    algorithms: list[str] = field(default_factory=lambda: ["RS256"])
    """Signature algorithms accepted. Never include "none"."""

    host: str = "127.0.0.1"
    port: int = 8000

    @classmethod
    def from_env(cls) -> "Settings":
        resource = _env("MCP_RESOURCE_URL").rstrip("/")
        if not resource.startswith("https://") and "localhost" not in resource:
            raise RuntimeError(
                "MCP_RESOURCE_URL must use https outside local development "
                "(RFC 8707 canonical URI)."
            )
        if "#" in resource:
            raise RuntimeError("MCP_RESOURCE_URL must not contain a fragment.")
        return cls(
            resource_url=resource,
            issuer_url=_env("MCP_AUTH_ISSUER").rstrip("/"),
            jwks_url=_env("MCP_JWKS_URL"),
            required_scopes=_scopes(os.environ.get("MCP_REQUIRED_SCOPES", "")),
            algorithms=_scopes(os.environ.get("MCP_ALGORITHMS", "RS256")),
            host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "8000")),
        )
