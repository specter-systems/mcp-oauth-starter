"""Tests for token verification.

The important one is `test_token_for_another_audience_is_rejected`. That is
the confused-deputy case: a perfectly valid, correctly signed, unexpired
token that was minted for a different resource server. If it passes, the
server is a replay vector.
"""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_oauth_starter.verifier import JwtTokenVerifier, _scopes_from

ISSUER = "https://auth.example.com"
AUDIENCE = "https://mcp.example.com/mcp"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def mint(**overrides) -> str:
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-123",
        "client_id": "https://app.example.com/client.json",
        "scope": "notes:read notes:write",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
    }
    claims.update(overrides)
    return jwt.encode(claims, _KEY, algorithm="RS256")


@pytest.fixture
def verifier(monkeypatch):
    v = JwtTokenVerifier(
        jwks_url="https://auth.example.com/.well-known/jwks.json",
        issuer=ISSUER,
        audience=AUDIENCE,
    )

    class _Key:
        key = _KEY.public_key()

    monkeypatch.setattr(v._jwks, "get_signing_key_from_jwt", lambda _t: _Key())
    return v


@pytest.mark.anyio
async def test_valid_token_is_accepted(verifier):
    token = await verifier.verify_token(mint())
    assert token is not None
    assert token.subject == "user-123"
    assert token.scopes == ["notes:read", "notes:write"]
    assert token.resource == AUDIENCE


@pytest.mark.anyio
async def test_token_for_another_audience_is_rejected(verifier):
    """RFC 8707 / MCP 2026-07-28 'Token Handling'. The confused-deputy guard."""
    assert await verifier.verify_token(mint(aud="https://other.example.com/mcp")) is None


@pytest.mark.anyio
async def test_token_from_another_issuer_is_rejected(verifier):
    assert await verifier.verify_token(mint(iss="https://evil.example.com")) is None


@pytest.mark.anyio
async def test_expired_token_is_rejected(verifier):
    assert await verifier.verify_token(mint(exp=int(time.time()) - 60)) is None


@pytest.mark.anyio
async def test_token_without_audience_is_rejected(verifier):
    """`require: aud` means a token that simply omits the claim cannot slip through."""
    claims = {
        "iss": ISSUER,
        "sub": "user-123",
        "exp": int(time.time()) + 300,
    }
    assert await verifier.verify_token(jwt.encode(claims, _KEY, algorithm="RS256")) is None


@pytest.mark.anyio
async def test_garbage_is_rejected_without_raising(verifier):
    assert await verifier.verify_token("not-a-jwt") is None


def test_none_algorithm_is_refused_at_construction():
    with pytest.raises(ValueError):
        JwtTokenVerifier(
            jwks_url="https://auth.example.com/jwks",
            issuer=ISSUER,
            audience=AUDIENCE,
            algorithms=["none"],
        )


@pytest.mark.parametrize(
    "claims,expected",
    [
        ({"scope": "a b"}, ["a", "b"]),
        ({"scp": ["a", "b"]}, ["a", "b"]),
        ({"scp": "a b"}, ["a", "b"]),
        ({}, []),
    ],
)
def test_scope_claim_shapes(claims, expected):
    """Entra emits `scp` as an array, Okta as a string, the RFC says `scope`."""
    assert _scopes_from(claims) == expected
