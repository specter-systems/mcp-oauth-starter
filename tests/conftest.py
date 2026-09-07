import os

os.environ.setdefault("MCP_RESOURCE_URL", "https://mcp.example.com/mcp")
os.environ.setdefault("MCP_AUTH_ISSUER", "https://auth.example.com")
os.environ.setdefault("MCP_JWKS_URL", "https://auth.example.com/.well-known/jwks.json")
os.environ.setdefault("MCP_REQUIRED_SCOPES", "")


import pytest


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"
