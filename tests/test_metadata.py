"""Tests for the RFC 9728 discovery document and the 401 challenge."""

import httpx
import pytest

from mcp_oauth_starter.server import app

RESOURCE = "https://mcp.example.com/mcp"


@pytest.fixture
def client():
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.com"
    )


@pytest.mark.anyio
async def test_protected_resource_metadata_is_published(client):
    """MCP servers MUST implement RFC 9728 protected resource metadata."""
    async with client as c:
        r = await c.get("/.well-known/oauth-protected-resource/mcp")
    assert r.status_code == 200
    doc = r.json()
    assert doc["resource"].rstrip("/") == RESOURCE
    assert "https://auth.example.com" in [
        s.rstrip("/") for s in doc["authorization_servers"]
    ]


@pytest.mark.anyio
async def test_unauthenticated_request_is_challenged(client):
    """401 plus a WWW-Authenticate pointing at the metadata document."""
    async with client as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
    assert r.status_code == 401
    challenge = r.headers.get("www-authenticate", "")
    assert challenge.lower().startswith("bearer")
    assert "resource_metadata=" in challenge


@pytest.mark.anyio
async def test_bad_token_is_rejected(client):
    async with client as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={
                "Authorization": "Bearer clearly-not-valid",
                "Accept": "application/json, text/event-stream",
            },
        )
    assert r.status_code == 401


@pytest.mark.anyio
async def test_challenge_advertises_required_scopes(monkeypatch):
    """MCP 2026-07-28 'Scope Selection Strategy': servers SHOULD send `scope`."""
    import importlib

    monkeypatch.setenv("MCP_REQUIRED_SCOPES", "notes:read notes:write")
    import mcp_oauth_starter.server as srv

    reloaded = importlib.reload(srv)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=reloaded.app),
        base_url="https://mcp.example.com",
    ) as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
    assert r.status_code == 401
    assert 'scope="notes:read notes:write"' in r.headers["www-authenticate"]
    monkeypatch.delenv("MCP_REQUIRED_SCOPES", raising=False)
    importlib.reload(srv)
