"""Bearer-token verification for an MCP resource server.

The one rule that matters here: a token is only acceptable if the
authorization server issued it *for this server*. MCP calls this out
explicitly (2026-07-28, "Token Handling"):

    MCP servers MUST validate that access tokens were issued specifically
    for them as the intended audience, according to RFC 8707 Section 2.

Skipping that check is the confused-deputy bug — a token minted for some
other service would be silently accepted here and replayed against your
backend. `audience=` in `jwt.decode` is what closes it.
"""

from __future__ import annotations

import logging

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)


class JwtTokenVerifier:
    """Verifies JWT access tokens against the authorization server's JWKS.

    Implements the SDK's `TokenVerifier` protocol: return an `AccessToken`
    when the token is good, `None` when it is not. Never raise for an
    untrusted token — a `None` return becomes the 401 the spec requires.
    """

    def __init__(
        self,
        *,
        jwks_url: str,
        issuer: str,
        audience: str,
        algorithms: list[str] | None = None,
    ) -> None:
        if algorithms and "none" in [a.lower() for a in algorithms]:
            raise ValueError('The "none" algorithm is never acceptable.')
        self._issuer = issuer
        self._audience = audience
        self._algorithms = algorithms or ["RS256"]
        # PyJWKClient caches keys and refetches on unknown `kid`, so key
        # rotation at the AS does not need a redeploy here.
        self._jwks = PyJWKClient(jwks_url, cache_keys=True)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self._algorithms,
                issuer=self._issuer,
                audience=self._audience,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.InvalidTokenError as exc:
            # Deliberately coarse: the client learns "401", not why.
            logger.info("rejected access token: %s", exc)
            return None
        except Exception:  # noqa: BLE001 - JWKS fetch/network failures
            logger.exception("could not verify access token")
            return None

        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("azp") or ""),
            scopes=_scopes_from(claims),
            expires_at=claims.get("exp"),
            resource=self._audience,
            subject=claims.get("sub"),
            claims=claims,
        )


def _scopes_from(claims: dict) -> list[str]:
    """Read scopes from either RFC 8693 `scope` or the `scp` array Entra/Okta emit."""
    raw = claims.get("scope")
    if isinstance(raw, str):
        return [s for s in raw.split() if s]
    scp = claims.get("scp")
    if isinstance(scp, str):
        return [s for s in scp.split() if s]
    if isinstance(scp, list):
        return [str(s) for s in scp]
    return []
