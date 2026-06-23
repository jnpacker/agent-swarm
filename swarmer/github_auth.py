"""GitHub App Installation Access Token (IAT) minting and refresh.

Swarmer uses Option A: mint a short-lived IAT server-side before launch and
inject it via the OpenShell Gateway provider API as GITHUB_TOKEN / GH_TOKEN.
The raw PEM private key never enters the sandbox.

Token lifetime:
- GitHub IATs are valid for up to 1 hour (GitHub default).
- For prompt-mode sessions (typically < 10 min) a single token at launch
  is sufficient.
- For TUI and server-mode sessions (potentially multi-hour), a background
  refresh loop re-mints and re-registers the provider every
  IAT_REFRESH_INTERVAL seconds so the token never expires mid-session.

PAT fallback:
- When no GitHub App is configured for a workspace the caller falls back to
  the session's assigned PAT exactly as before.
- When a GitHub App IS configured but IAT minting fails at launch time and a
  PAT is available, launch continues using the PAT (graceful degradation).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

import httpx
import jwt  # PyJWT

if TYPE_CHECKING:
    from swarmer.models.github_app import GitHubApp

log = logging.getLogger(__name__)

# Mint a fresh IAT this many seconds before the current one would expire.
# GitHub IATs last 3600 s; refresh at 3000 s (10 min before expiry).
IAT_LIFETIME_S = 3600
IAT_REFRESH_INTERVAL = 3000  # seconds between re-mints for long-running sessions

# GitHub JWT is short-lived (10 min max); use 9 min to be safe.
_JWT_LIFETIME_S = 9 * 60


def _build_jwt(app: "GitHubApp") -> str:
    """Sign a GitHub App JWT using the App's RSA private key (RS256)."""
    now = int(time.time())
    payload = {
        "iat": now - 60,          # 1 min in the past to tolerate clock skew
        "exp": now + _JWT_LIFETIME_S,
        "iss": app.app_id,
    }
    return jwt.encode(payload, app.private_key, algorithm="RS256")


async def mint_installation_token(app: "GitHubApp") -> str:
    """Exchange a GitHub App JWT for a short-lived Installation Access Token.

    Returns the raw token string.  Raises httpx.HTTPStatusError on failure.
    """
    signed_jwt = _build_jwt(app)
    url = f"https://api.github.com/app/installations/{app.installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {signed_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    token: str = data["token"]
    expires_at = data.get("expires_at", "unknown")
    log.info(
        "github_auth: minted IAT for app_id=%s installation_id=%s expires_at=%s",
        app.app_id, app.installation_id, expires_at,
    )
    return token


async def start_token_refresh_loop(
    app: "GitHubApp",
    session_id: int,
    provider_name: str,
) -> None:
    """Background task: re-mint an IAT and update the OpenShell provider on a fixed schedule.

    Runs until cancelled (i.e., until the session stops and the task is
    collected by the event loop).  Intended for TUI and server-mode sessions
    whose lifetime can exceed the 1-hour IAT validity window.

    Args:
        app:           The GitHubApp ORM object (credentials already resolved;
                       private_key property decrypts on access).
        session_id:    Used only for log context.
        provider_name: The OpenShell Gateway provider name to update.
    """
    from swarmer import openshell_client

    # Snapshot the credentials we need — the ORM object may be detached after
    # the DB session expires, so read the key once upfront.
    app_id = app.app_id
    installation_id = app.installation_id
    private_key = app.private_key  # decrypts here; stored in local var

    # Build a lightweight stand-in to avoid holding the ORM object.
    class _AppSnapshot:
        pass

    snap = _AppSnapshot()
    snap.app_id = app_id  # type: ignore[attr-defined]
    snap.installation_id = installation_id  # type: ignore[attr-defined]
    snap.private_key = private_key  # type: ignore[attr-defined]

    log.info(
        "github_auth: starting IAT refresh loop for session %d provider %s (interval=%ds)",
        session_id, provider_name, IAT_REFRESH_INTERVAL,
    )
    try:
        while True:
            await asyncio.sleep(IAT_REFRESH_INTERVAL)
            try:
                new_token = await mint_installation_token(snap)  # type: ignore[arg-type]
                await openshell_client.ensure_provider(
                    provider_name,
                    "github",
                    {},
                    credentials={
                        "GITHUB_TOKEN": new_token,
                        "GH_TOKEN": new_token,
                    },
                )
                log.info(
                    "github_auth: refreshed IAT for session %d provider %s",
                    session_id, provider_name,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                log.warning(
                    "github_auth: IAT refresh failed for session %d — will retry next interval",
                    session_id, exc_info=True,
                )
    except asyncio.CancelledError:
        log.info(
            "github_auth: IAT refresh loop cancelled for session %d provider %s",
            session_id, provider_name,
        )
