"""
OIDC bearer-token auth for a remote/hosted OpenShell gateway (ACM-41655).

The OpenShell SDK already ships a complete OIDC auto-refresh implementation
(`SandboxClient.from_active_cluster()` / `_OidcRefresher`), but it reads and
writes the token bundle to `~/.config/openshell/gateways/<name>/
oidc_token.json` on disk. That's the right model for the `openshell` CLI, but
it conflicts with this repo's Sensitive Data Policy ("favor encrypted
database over Kubernetes objects/files" — see AGENTS.md): Swarmer never
writes credentials to plaintext files.

This module reimplements the same RFC 6749 refresh_token-grant flow, but the
token bundle lives encrypted in Swarmer's own DB
(`openshell_gateway_credentials` — a singleton row, see
swarmer/models/openshell_gateway_credential.py) instead of a file.

Flow:
  1. An operator seeds the initial refresh token out-of-band (e.g. from
     `openshell gateway login` on a workstation) via
     scripts/openshell_seed_oidc_credential.py — Swarmer itself never
     performs the interactive OIDC login.
  2. At Swarmer startup, `load_from_db()` reads the encrypted bundle into an
     in-process singleton (`OidcGatewayAuth`) and captures the running event
     loop so the sync token-provider callable can dispatch DB writes back
     onto it.
  3. `get_token_provider()` returns a zero-arg callable handed to
     `SandboxClient(bearer_token=...)`. The OpenShell SDK calls it before
     every gRPC RPC (see `openshell.sandbox.SandboxClient.__init__`), so it
     must be fast: it only makes a blocking HTTP call to the IdP when the
     cached access token is near expiry.
  4. Refreshed bundles — including any rotated refresh_token (Keycloak
     rotates by default) — are written back to the DB so a Swarmer restart
     doesn't strand the credential on an invalidated refresh_token.

Thread-safety: the token-provider callable runs on whatever thread the gRPC
channel's interceptor uses (not necessarily the asyncio event-loop thread),
so refresh is coordinated with a plain `threading.Lock` and the DB
write-back is dispatched via `asyncio.run_coroutine_threadsafe`.

Remote-pod orchestration: when Swarmer runs as a K8s pod, seeding/rotating
the credential means running scripts/openshell_seed_oidc_credential.py via
`kubectl exec` into the *running* pod (see `make openshell-oidc-seed`) — a
separate one-shot process that writes straight to the DB and exits; it does
not share memory with the long-running Swarmer server process. To avoid
requiring a pod restart for that write to take effect, `current_access_token()`
lazily re-reads the DB (via the same `run_coroutine_threadsafe` mechanism)
whenever it has no usable bundle yet, or after an `invalid_grant` — so a
`kubectl exec` seed/re-seed is picked up on the *next* OpenShell API call,
no restart required.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

import httpx

log = logging.getLogger(__name__)

# Refresh this many seconds before actual expiry so a slow RPC doesn't race
# past a hard expiry boundary.
_EXPIRY_GRACE_SECONDS = 60
# Timeout for the best-effort DB write-back of a rotated refresh token.
_WRITE_BACK_TIMEOUT = 5.0


class OidcAuthError(RuntimeError):
    """Raised when OIDC discovery/refresh fails or the credential is missing."""


class _InvalidGrantError(OidcAuthError):
    """The IdP rejected the refresh_token (expired, revoked, or rotated away)."""


class OidcGatewayAuth:
    """In-process, lock-coordinated OAuth2 refresh for the global OpenShell
    gateway credential."""

    def __init__(self, issuer: str, client_id: str, audience: str = ""):
        self._issuer = issuer.rstrip("/")
        self._client_id = client_id
        self._audience = audience
        self._lock = threading.Lock()
        self._bundle: dict | None = None
        self._token_endpoint: str | None = None
        self._http = httpx.Client(follow_redirects=False, timeout=15.0)
        # Captured by set_event_loop() at startup so the sync callable can
        # dispatch the async DB write-back from whatever thread calls it.
        self._loop: asyncio.AbstractEventLoop | None = None

    def close(self) -> None:
        self._http.close()

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def seed(self, refresh_token: str, access_token: str = "", expires_at: int | None = None) -> None:
        """Populate the in-memory bundle (called once at startup after DB load)."""
        with self._lock:
            self._bundle = {
                "refresh_token": refresh_token,
                "access_token": access_token,
                "expires_at": expires_at,
            }

    def current_access_token(self) -> str:
        """Zero-arg callable passed as `SandboxClient(bearer_token=...)`.

        Called by the OpenShell SDK's gRPC interceptor before every RPC —
        must return quickly; only refreshes against the IdP when stale.
        """
        with self._lock:
            if self._bundle is None or not self._bundle.get("refresh_token"):
                # Not seeded yet in this process's memory — check the DB
                # once before giving up. Lets a `kubectl exec` seed into a
                # running pod take effect on the very next call, with no
                # restart required.
                if not self._reload_from_db():
                    raise OidcAuthError(
                        "OpenShell OIDC credential not configured — seed it with "
                        "scripts/openshell_seed_oidc_credential.py"
                    )
            if self._is_fresh(self._bundle):
                return self._bundle["access_token"]
            try:
                self._bundle = self._refresh(self._bundle)
            except _InvalidGrantError:
                # Our in-memory refresh_token may be stale relative to the DB
                # (e.g. an operator just re-seeded a corrected/rotated token
                # via `kubectl exec` while this pod kept running). Check once
                # before surfacing the failure.
                if self._reload_from_db() and self._bundle.get("refresh_token"):
                    try:
                        self._bundle = self._refresh(self._bundle)
                    except _InvalidGrantError:
                        log.error(
                            "OpenShell OIDC refresh_token rejected (invalid_grant), "
                            "even after reloading from DB — re-seed with "
                            "scripts/openshell_seed_oidc_credential.py"
                        )
                        raise
                else:
                    log.error(
                        "OpenShell OIDC refresh_token rejected (invalid_grant) — "
                        "re-seed with scripts/openshell_seed_oidc_credential.py"
                    )
                    raise
            self._write_back(self._bundle)
            return self._bundle["access_token"]

    def _reload_from_db(self) -> bool:
        """Best-effort reload of the credential bundle from the DB.

        Must be called while holding self._lock. Returns True if a usable
        bundle was found and adopted.
        """
        if self._loop is None:
            return False
        try:
            fut = asyncio.run_coroutine_threadsafe(_load_bundle(), self._loop)
            bundle = fut.result(timeout=_WRITE_BACK_TIMEOUT)
        except Exception:
            log.warning("Failed to reload OpenShell OIDC credential from DB", exc_info=True)
            return False
        if bundle is None:
            return False
        self._bundle = bundle
        return True

    @staticmethod
    def _is_fresh(bundle: dict) -> bool:
        access_token = bundle.get("access_token")
        if not access_token:
            return False
        exp = bundle.get("expires_at")
        if exp is None:
            return True
        return int(time.time()) + _EXPIRY_GRACE_SECONDS < exp

    def _discover_token_endpoint(self) -> str:
        if self._token_endpoint is not None:
            return self._token_endpoint
        discovery_url = f"{self._issuer}/.well-known/openid-configuration"
        try:
            resp = self._http.get(discovery_url)
        except httpx.HTTPError as e:
            raise OidcAuthError(f"OIDC discovery failed for {self._issuer}: {e}") from e
        if not 200 <= resp.status_code < 300:
            raise OidcAuthError(
                f"OIDC discovery failed: HTTP {resp.status_code} from {discovery_url}"
            )
        disco = resp.json()
        # Validate the discovery document's issuer matches the configured
        # one — without this a misdirected/malicious discovery response
        # could steer the refresh_token POST to an attacker-controlled
        # endpoint.
        discovered_issuer = str(disco.get("issuer", "")).rstrip("/")
        if discovered_issuer != self._issuer:
            raise OidcAuthError(
                f"OIDC discovery issuer mismatch: expected '{self._issuer}', "
                f"got '{discovered_issuer}'"
            )
        endpoint = disco.get("token_endpoint")
        if not endpoint:
            raise OidcAuthError("OIDC discovery response missing token_endpoint")
        self._token_endpoint = endpoint
        return endpoint

    def _refresh(self, bundle: dict) -> dict:
        token_endpoint = self._discover_token_endpoint()
        data = {
            "grant_type": "refresh_token",
            "refresh_token": bundle["refresh_token"],
            "client_id": self._client_id,
        }
        if self._audience:
            data["audience"] = self._audience
        try:
            resp = self._http.post(token_endpoint, data=data)
        except httpx.HTTPError as e:
            raise OidcAuthError(f"OIDC token refresh failed: {type(e).__name__}: {e}") from e
        if resp.status_code != 200:
            error_code = None
            with contextlib.suppress(Exception):
                error_code = resp.json().get("error")
            if error_code == "invalid_grant":
                raise _InvalidGrantError(f"OIDC refresh rejected: {resp.text[:200]}")
            raise OidcAuthError(
                f"OIDC token refresh failed: HTTP {resp.status_code}: {resp.text[:200]}"
            )
        token = resp.json()
        access_token = token.get("access_token")
        if not access_token:
            raise OidcAuthError("OIDC refresh response missing access_token")
        expires_at = token.get("expires_at")
        if expires_at is None:
            expires_in = token.get("expires_in")
            if isinstance(expires_in, (int, float)):
                expires_at = int(time.time()) + int(expires_in)
        return {
            "access_token": access_token,
            # Refresh-token rotation: Keycloak (and Entra in strict mode)
            # reissue and invalidate the old refresh_token on every refresh.
            "refresh_token": token.get("refresh_token", bundle["refresh_token"]),
            "expires_at": int(expires_at) if expires_at is not None else None,
        }

    def _write_back(self, bundle: dict) -> None:
        """Best-effort persist of the (possibly rotated) bundle to the DB."""
        if self._loop is None:
            log.warning("OIDC token refreshed but no event loop registered — not persisted to DB")
            return
        try:
            fut = asyncio.run_coroutine_threadsafe(_persist_bundle(bundle), self._loop)
            fut.result(timeout=_WRITE_BACK_TIMEOUT)
        except Exception:
            log.warning("Failed to persist refreshed OpenShell OIDC token to DB", exc_info=True)


_instance: OidcGatewayAuth | None = None


async def load_from_db() -> OidcGatewayAuth | None:
    """Load the singleton OIDC credential row into an in-process auth
    instance. Called once at Swarmer startup (only when
    settings.openshell_auth_mode == "oidc"). Returns None (and logs a
    warning) if not configured/seeded yet — Swarmer keeps starting; the
    first OpenShell call lazily retries the DB read (see
    OidcGatewayAuth._reload_from_db) before raising a clear OidcAuthError.
    """
    global _instance
    from swarmer.config import settings

    if not settings.openshell_oidc_issuer or not settings.openshell_oidc_client_id:
        log.warning(
            "OPENSHELL_AUTH_MODE=oidc but OPENSHELL_OIDC_ISSUER / "
            "OPENSHELL_OIDC_CLIENT_ID are not configured"
        )
        return None

    _instance = OidcGatewayAuth(
        issuer=settings.openshell_oidc_issuer,
        client_id=settings.openshell_oidc_client_id,
        audience=settings.openshell_oidc_audience,
    )
    with contextlib.suppress(RuntimeError):
        _instance.set_event_loop(asyncio.get_running_loop())

    bundle = await _load_bundle()
    if bundle is None:
        log.warning(
            "No OpenShell OIDC credential found in DB — seed one with "
            "scripts/openshell_seed_oidc_credential.py"
        )
        return _instance

    _instance.seed(bundle["refresh_token"], bundle["access_token"], bundle["expires_at"])
    log.info("Loaded OpenShell OIDC gateway credential from DB")
    return _instance


async def _load_bundle() -> dict | None:
    """Read the singleton credential row and return a decrypted bundle dict,
    or None if no row / no refresh token is stored yet."""
    from sqlalchemy import select

    from swarmer.database import get_db
    from swarmer.models.openshell_gateway_credential import OpenshellGatewayCredential

    row = None
    async for db in get_db():
        row = (await db.execute(select(OpenshellGatewayCredential).limit(1))).scalar_one_or_none()
        break

    if row is None or not row.refresh_token_enc:
        return None

    expires_at = (
        int(row.access_token_expires_at.replace(tzinfo=timezone.utc).timestamp())
        if row.access_token_expires_at
        else None
    )
    return {"refresh_token": row.refresh_token, "access_token": row.access_token, "expires_at": expires_at}


async def _persist_bundle(bundle: dict) -> None:
    from sqlalchemy import select

    from swarmer.database import get_db
    from swarmer.models.openshell_gateway_credential import OpenshellGatewayCredential

    async for db in get_db():
        row = (await db.execute(select(OpenshellGatewayCredential).limit(1))).scalar_one_or_none()
        if row is None:
            row = OpenshellGatewayCredential()
            db.add(row)
        row.refresh_token = bundle["refresh_token"]
        row.access_token = bundle.get("access_token", "")
        expires_at = bundle.get("expires_at")
        row.access_token_expires_at = (
            datetime.fromtimestamp(expires_at, tz=timezone.utc).replace(tzinfo=None)
            if expires_at
            else None
        )
        await db.commit()
        break


async def get_status() -> dict:
    """Non-secret status for the OpenShell Gateway admin config page.

    Deployment-level settings (auth_mode/gateway_url/issuer/client_id/
    audience) are env-configured and reported read-only here; only the
    refresh/access token bundle is DB-managed and editable via the page.
    """
    from swarmer.config import settings

    bundle = await _load_bundle()
    return {
        "auth_mode": settings.openshell_auth_mode,
        "gateway_url": settings.openshell_gateway_url,
        "oidc_issuer": settings.openshell_oidc_issuer,
        "oidc_client_id": settings.openshell_oidc_client_id,
        "oidc_audience": settings.openshell_oidc_audience,
        "oidc_tls_ca": settings.openshell_oidc_tls_ca,
        "oidc_configured": bool(settings.openshell_oidc_issuer and settings.openshell_oidc_client_id),
        "has_credential": bundle is not None,
        "access_token_expires_at": bundle.get("expires_at") if bundle else None,
        "loaded_in_process": _instance is not None and _instance._bundle is not None,
    }


async def set_credential(refresh_token: str, access_token: str = "", expires_at: int | None = None) -> None:
    """Seed/rotate the credential from the admin config page.

    Always writes to the DB (so it survives even if OPENSHELL_AUTH_MODE
    isn't "oidc" yet — e.g. pre-seeding before a redeploy that flips it on).
    If this process already has a live `OidcGatewayAuth` instance (auth_mode
    is "oidc" and load_from_db() ran at startup), also updates it in-memory
    so the change is visible to *this* process immediately, without waiting
    for the lazy DB reload on the next OpenShell call.
    """
    bundle = {"refresh_token": refresh_token, "access_token": access_token, "expires_at": expires_at}
    await _persist_bundle(bundle)
    if _instance is not None:
        _instance.seed(refresh_token, access_token, expires_at)


async def clear_credential() -> None:
    """Remove the stored credential (e.g. before re-seeding a corrected token)."""
    from sqlalchemy import select

    from swarmer.database import get_db
    from swarmer.models.openshell_gateway_credential import OpenshellGatewayCredential

    async for db in get_db():
        row = (await db.execute(select(OpenshellGatewayCredential).limit(1))).scalar_one_or_none()
        if row is not None:
            await db.delete(row)
            await db.commit()
        break
    if _instance is not None:
        _instance._bundle = None


def get_token_provider() -> Callable[[], str]:
    """Return the zero-arg bearer-token callable for SandboxClient()."""
    if _instance is None:
        raise OidcAuthError(
            "OpenShell OIDC auth not initialized — load_from_db() must run at "
            "startup before the OpenShell client is used"
        )
    return _instance.current_access_token
