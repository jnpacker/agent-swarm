"""
Tests for swarmer.openshell_oidc — DB-backed OIDC bearer-token auth for a
remote/hosted OpenShell gateway (ACM-41655).

Covers:
  - current_access_token() returns the cached token when fresh, refreshes via
    the IdP's discovered token_endpoint when stale.
  - Refresh-token rotation is honored (new refresh_token replaces the old one).
  - invalid_grant surfaces as _InvalidGrantError.
  - Discovery issuer mismatch is rejected (anti-SSRF).
  - load_from_db() / _persist_bundle() round-trip through the encrypted DB
    singleton row.
  - get_token_provider() raises before load_from_db() has run.
"""
import asyncio
import os
import sys
import time

import httpx
import pytest
import pytest_asyncio
import respx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swarmer.database import Base  # noqa: E402
import swarmer.openshell_oidc as oidc  # noqa: E402

ISSUER = "https://keycloak.example.com/realms/ambient-code"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"


def _discovery_route():
    return respx.get(DISCOVERY_URL).mock(
        return_value=httpx.Response(200, json={"issuer": ISSUER, "token_endpoint": TOKEN_ENDPOINT})
    )


# ---------------------------------------------------------------------------
# OidcGatewayAuth — in-memory refresh logic
# ---------------------------------------------------------------------------


def test_current_access_token_returns_cached_when_fresh():
    auth = oidc.OidcGatewayAuth(issuer=ISSUER, client_id="swarm-client")
    auth.seed(refresh_token="rt-1", access_token="at-cached", expires_at=int(time.time()) + 3600)

    with respx.mock:
        # No HTTP calls expected — respx raises if any route is hit.
        token = auth.current_access_token()

    assert token == "at-cached"


def test_current_access_token_refreshes_when_stale():
    auth = oidc.OidcGatewayAuth(issuer=ISSUER, client_id="swarm-client")
    auth.seed(refresh_token="rt-1", access_token="at-old", expires_at=int(time.time()) - 10)

    with respx.mock:
        _discovery_route()
        refresh_route = respx.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "at-new",
                    "refresh_token": "rt-2",  # rotated
                    "expires_in": 300,
                },
            )
        )
        token = auth.current_access_token()

    assert token == "at-new"
    assert refresh_route.called
    request = refresh_route.calls.last.request
    body = request.content.decode()
    assert "grant_type=refresh_token" in body
    assert "refresh_token=rt-1" in body
    assert "client_id=swarm-client" in body
    # Rotated refresh_token is retained in memory for the next refresh.
    assert auth._bundle["refresh_token"] == "rt-2"


def test_current_access_token_no_expiry_treated_as_fresh():
    """A bundle with no expires_at (IdP didn't return expires_in) is treated
    as always-fresh, matching the SDK's own _is_fresh semantics."""
    auth = oidc.OidcGatewayAuth(issuer=ISSUER, client_id="swarm-client")
    auth.seed(refresh_token="rt-1", access_token="at-1", expires_at=None)

    with respx.mock:
        token = auth.current_access_token()

    assert token == "at-1"


def test_current_access_token_missing_credential_raises():
    auth = oidc.OidcGatewayAuth(issuer=ISSUER, client_id="swarm-client")
    with pytest.raises(oidc.OidcAuthError):
        auth.current_access_token()


def test_refresh_invalid_grant_raises():
    auth = oidc.OidcGatewayAuth(issuer=ISSUER, client_id="swarm-client")
    auth.seed(refresh_token="rt-dead", access_token="at-old", expires_at=int(time.time()) - 10)

    with respx.mock:
        _discovery_route()
        respx.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(400, json={"error": "invalid_grant"})
        )
        with pytest.raises(oidc._InvalidGrantError):
            auth.current_access_token()


def test_discovery_issuer_mismatch_rejected():
    auth = oidc.OidcGatewayAuth(issuer=ISSUER, client_id="swarm-client")
    auth.seed(refresh_token="rt-1", access_token="at-old", expires_at=int(time.time()) - 10)

    with respx.mock:
        respx.get(DISCOVERY_URL).mock(
            return_value=httpx.Response(
                200, json={"issuer": "https://evil.example.com", "token_endpoint": "https://evil.example.com/token"}
            )
        )
        with pytest.raises(oidc.OidcAuthError, match="issuer mismatch"):
            auth.current_access_token()


def test_audience_included_when_configured():
    auth = oidc.OidcGatewayAuth(issuer=ISSUER, client_id="swarm-client", audience="swarm-aud")
    auth.seed(refresh_token="rt-1", access_token="at-old", expires_at=int(time.time()) - 10)

    with respx.mock:
        _discovery_route()
        refresh_route = respx.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"access_token": "at-new", "expires_in": 300})
        )
        auth.current_access_token()

    body = refresh_route.calls.last.request.content.decode()
    assert "audience=swarm-aud" in body


def test_get_token_provider_raises_before_load():
    oidc._instance = None
    with pytest.raises(oidc.OidcAuthError):
        oidc.get_token_provider()


# ---------------------------------------------------------------------------
# load_from_db() / _persist_bundle() — encrypted DB round-trip
# ---------------------------------------------------------------------------

_engine = create_async_engine("sqlite+aiosqlite://", echo=False)
_TestSession = async_sessionmaker(_engine, expire_on_commit=False)


async def _override_get_db():
    async with _TestSession() as session:
        yield session


@pytest_asyncio.fixture(autouse=True)
async def _setup_db(monkeypatch):
    from swarmer.crypto import init_crypto
    init_crypto("auth/secret.key")

    import swarmer.models  # noqa: F401
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    monkeypatch.setattr("swarmer.database.get_db", _override_get_db)

    from swarmer.config import settings
    orig_issuer = settings.openshell_oidc_issuer
    orig_client_id = settings.openshell_oidc_client_id
    orig_audience = settings.openshell_oidc_audience
    settings.openshell_oidc_issuer = ISSUER
    settings.openshell_oidc_client_id = "swarm-client"
    settings.openshell_oidc_audience = ""

    yield

    settings.openshell_oidc_issuer = orig_issuer
    settings.openshell_oidc_client_id = orig_client_id
    settings.openshell_oidc_audience = orig_audience
    oidc._instance = None
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.asyncio
async def test_load_from_db_no_row_returns_instance_without_bundle():
    instance = await oidc.load_from_db()
    assert instance is not None
    # current_access_token() lazily re-checks the DB via
    # run_coroutine_threadsafe — must be called from a *different* thread
    # than the one running the event loop (as it is in production, via the
    # gRPC interceptor thread), or the DB coroutine can never run and it
    # blocks for the full _WRITE_BACK_TIMEOUT before giving up.
    with pytest.raises(oidc.OidcAuthError):
        await asyncio.to_thread(instance.current_access_token)


@pytest.mark.asyncio
async def test_current_access_token_lazily_picks_up_db_seed_without_restart():
    """Simulates `make openshell-oidc-seed` / the admin config page writing
    a credential into the DB of an *already-running* process — no restart
    required, the next call picks it up."""
    instance = await oidc.load_from_db()
    assert instance is not None

    await oidc.set_credential("rt-seeded-live", "at-seeded-live", int(time.time()) + 3600)
    # set_credential() also updates the passed-in `_instance` directly (see
    # openshell_oidc.set_credential), but exercise the pure DB-lazy-reload
    # path too by constructing a second, independent instance that never had
    # seed()/set_credential() called on it directly.
    other = oidc.OidcGatewayAuth(issuer=ISSUER, client_id="swarm-client")
    other.set_event_loop(asyncio.get_running_loop())

    token = await asyncio.to_thread(other.current_access_token)
    assert token == "at-seeded-live"


@pytest.mark.asyncio
async def test_invalid_grant_recovers_via_db_reseed_without_restart(monkeypatch):
    """If an operator re-seeds a corrected/rotated refresh token into the DB
    of a running pod after the in-memory one dies with invalid_grant, the
    very next call recovers without a restart."""
    auth = oidc.OidcGatewayAuth(issuer=ISSUER, client_id="swarm-client")
    auth.set_event_loop(asyncio.get_running_loop())
    auth.seed(refresh_token="rt-dead", access_token="at-old", expires_at=int(time.time()) - 10)

    async def _fake_load_bundle():
        return {"refresh_token": "rt-fresh", "access_token": "", "expires_at": None}

    monkeypatch.setattr(oidc, "_load_bundle", _fake_load_bundle)

    with respx.mock:
        _discovery_route()
        route = respx.post(TOKEN_ENDPOINT).mock(
            side_effect=[
                httpx.Response(400, json={"error": "invalid_grant"}),
                httpx.Response(200, json={"access_token": "at-recovered", "expires_in": 300}),
            ]
        )
        token = await asyncio.to_thread(auth.current_access_token)

    assert token == "at-recovered"
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_load_from_db_missing_settings_returns_none():
    from swarmer.config import settings
    settings.openshell_oidc_issuer = ""
    instance = await oidc.load_from_db()
    assert instance is None


@pytest.mark.asyncio
async def test_persist_bundle_then_load_round_trips_encrypted():
    from sqlalchemy import select
    from swarmer.models.openshell_gateway_credential import OpenshellGatewayCredential

    future_expiry = int(time.time()) + 3600
    await oidc._persist_bundle(
        {"refresh_token": "rt-secret", "access_token": "at-secret", "expires_at": future_expiry}
    )

    async for db in _override_get_db():
        row = (await db.execute(select(OpenshellGatewayCredential).limit(1))).scalar_one()
        break

    # Encrypted at rest — the ciphertext must not contain the plaintext secret.
    assert "rt-secret" not in row.refresh_token_enc
    assert row.refresh_token == "rt-secret"
    assert row.access_token == "at-secret"

    instance = await oidc.load_from_db()
    assert instance is not None
    token = instance.current_access_token()
    assert token == "at-secret"


@pytest.mark.asyncio
async def test_persist_bundle_updates_existing_row():
    await oidc._persist_bundle({"refresh_token": "rt-1", "access_token": "at-1", "expires_at": None})
    await oidc._persist_bundle({"refresh_token": "rt-2", "access_token": "at-2", "expires_at": None})

    from sqlalchemy import select, func
    from swarmer.models.openshell_gateway_credential import OpenshellGatewayCredential

    async for db in _override_get_db():
        count = (await db.execute(select(func.count()).select_from(OpenshellGatewayCredential))).scalar_one()
        row = (await db.execute(select(OpenshellGatewayCredential).limit(1))).scalar_one()
        break

    assert count == 1
    assert row.refresh_token == "rt-2"


# ---------------------------------------------------------------------------
# get_status() / set_credential() / clear_credential() — admin config page
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_status_reports_unconfigured_by_default():
    from swarmer.config import settings
    settings.openshell_oidc_issuer = ""
    settings.openshell_oidc_client_id = ""

    status = await oidc.get_status()
    assert status["oidc_configured"] is False
    assert status["has_credential"] is False
    assert status["loaded_in_process"] is False


@pytest.mark.asyncio
async def test_set_credential_persists_and_updates_live_instance():
    instance = await oidc.load_from_db()
    assert instance is not None

    await oidc.set_credential("rt-new", "at-new", int(time.time()) + 3600)

    status = await oidc.get_status()
    assert status["has_credential"] is True
    assert status["loaded_in_process"] is True  # set_credential() updated `instance` in place

    token = await asyncio.to_thread(instance.current_access_token)
    assert token == "at-new"


@pytest.mark.asyncio
async def test_set_credential_works_without_a_live_instance():
    """Pre-seeding before OPENSHELL_AUTH_MODE=oidc is deployed/redeployed —
    _instance is None, only the DB write matters."""
    assert oidc._instance is None
    await oidc.set_credential("rt-preseed")

    status = await oidc.get_status()
    assert status["has_credential"] is True
    assert status["loaded_in_process"] is False


@pytest.mark.asyncio
async def test_clear_credential_removes_row_and_live_bundle():
    instance = await oidc.load_from_db()
    await oidc.set_credential("rt-to-clear", "at-to-clear", int(time.time()) + 3600)
    assert (await oidc.get_status())["has_credential"] is True

    await oidc.clear_credential()

    status = await oidc.get_status()
    assert status["has_credential"] is False
    assert instance._bundle is None
