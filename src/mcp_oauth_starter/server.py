"""A remote MCP server that requires OAuth 2.1 authorization.

Spec revision: 2026-07-28. Two things follow from that revision and are
worth knowing before you copy this:

* The protocol core is now stateless. There is no `initialize`/`initialized`
  handshake and no `Mcp-Session-Id` header, so this server scales behind a
  plain round-robin load balancer with no shared session store.
* Dynamic Client Registration is deprecated in favour of Client ID Metadata
  Documents. That is a concern for the *authorization server*, not for this
  resource server — but it is the reason not to build new work against a
  DCR-only AS.

What this file wires up:

    AuthSettings          -> publishes RFC 9728 protected resource metadata
                             at /.well-known/oauth-protected-resource/...
    JwtTokenVerifier      -> validates signature, issuer and audience
    validate_token_resource=True
                          -> refuses any token not minted for THIS server
"""

from __future__ import annotations

from typing import Annotated

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl, Field

from .challenge import ScopeChallengeMiddleware
from .settings import Settings
from .verifier import JwtTokenVerifier

settings = Settings.from_env()

mcp = MCPServer(
    name="mcp-oauth-starter",
    title="OAuth-protected MCP starter",
    version="0.1.0",
    instructions=(
        "A minimal remote MCP server demonstrating OAuth 2.1 resource-server "
        "authorization under the 2026-07-28 spec revision."
    ),
    token_verifier=JwtTokenVerifier(
        jwks_url=settings.jwks_url,
        issuer=settings.issuer_url,
        audience=settings.resource_url,
        algorithms=settings.algorithms,
    ),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(settings.issuer_url),
        resource_server_url=AnyHttpUrl(settings.resource_url),
        required_scopes=settings.required_scopes or None,
        # Belt and braces: the verifier already pins the audience, and the
        # bearer middleware refuses anything whose resource is not us.
        validate_token_resource=True,
    ),
)


class InsufficientScope(Exception):
    """Raised when a caller is authenticated but not entitled to this tool."""


def require_scope(scope: str) -> None:
    """Guard a single tool behind one scope.

    `required_scopes` on AuthSettings gates the whole server. This gates one
    tool, which is what you want when a connector exposes both read and write
    operations and you would rather not hand every caller write access.
    """
    token = get_access_token()
    if token is None or scope not in token.scopes:
        raise InsufficientScope(
            f"This tool requires the '{scope}' scope. Re-authorize with it "
            "included and try again."
        )


@mcp.tool()
def whoami() -> dict[str, object]:
    """Report the subject, client and scopes attached to the calling token.

    The first thing worth having when you are debugging someone else's OAuth
    setup at 2am: proof of which identity actually arrived.
    """
    token = get_access_token()
    if token is None:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "subject": token.subject,
        "client_id": token.client_id,
        "scopes": token.scopes,
        "resource": token.resource,
        "expires_at": token.expires_at,
    }


@mcp.tool()
def echo(
    message: Annotated[str, Field(max_length=4096, description="Text to echo back.")],
) -> str:
    """Return the message unchanged. Useful as a liveness probe through the full auth path."""
    return message


@mcp.tool()
def write_note(
    text: Annotated[str, Field(max_length=4096, description="Note body.")],
) -> str:
    """Example of a write operation gated behind its own scope."""
    require_scope("notes:write")
    # A real connector would persist here. Kept deliberately inert.
    return f"Would have written {len(text)} characters."


# The SDK does not emit the RFC 6750 `scope` parameter on its challenge;
# this wrapper adds it so clients can skip a metadata fetch on cold start.
app = ScopeChallengeMiddleware(
    mcp.streamable_http_app(), settings.required_scopes
)


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
