"""REST API — OpenShell Gateway admin config (ACM-41655).

Admin-only. Lets a Swarmer admin seed/rotate the encrypted OIDC refresh
token used to connect to a remote/hosted OpenShell gateway (e.g. the "swarm"
gateway) from a web UI, instead of `kubectl exec`-ing a script into the pod.

Deployment-level settings (OPENSHELL_AUTH_MODE, OPENSHELL_GATEWAY_URL,
OPENSHELL_OIDC_ISSUER/CLIENT_ID/AUDIENCE) remain env-configured (a redeploy
is still required to change those) — only the token bundle is DB-managed and
editable here, matching the "encrypted database over Kubernetes objects"
Sensitive Data Policy.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from swarmer import workspace_acl
from swarmer.api.deps import require_api_auth
from swarmer.api.schemas import (
    MessageOut,
    OpenshellGatewayCredentialIn,
    OpenshellGatewayStatusOut,
)
from swarmer.database import get_db
from swarmer.k8s_auth import TokenIdentity

router = APIRouter(tags=["openshell-gateway"], dependencies=[Depends(require_api_auth)])


async def _require_admin(identity: TokenIdentity, db: AsyncSession) -> None:
    if not await workspace_acl.is_admin(db, identity.username, identity.groups):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only a Swarmer admin can do that.",
        )


@router.get("/openshell-gateway", response_model=OpenshellGatewayStatusOut)
async def get_openshell_gateway_status(
    identity: TokenIdentity = Depends(require_api_auth),
    db: AsyncSession = Depends(get_db),
):
    await _require_admin(identity, db)
    from swarmer import openshell_oidc

    return OpenshellGatewayStatusOut(**await openshell_oidc.get_status())


@router.post("/openshell-gateway/credential", response_model=MessageOut)
async def set_openshell_gateway_credential(
    body: OpenshellGatewayCredentialIn,
    identity: TokenIdentity = Depends(require_api_auth),
    db: AsyncSession = Depends(get_db),
):
    await _require_admin(identity, db)
    from swarmer import openshell_oidc

    refresh_token = body.refresh_token.strip()
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="refresh_token is required.",
        )
    await openshell_oidc.set_credential(refresh_token, body.access_token, body.expires_at)
    return MessageOut(detail="OpenShell OIDC credential saved.")


@router.delete("/openshell-gateway/credential", response_model=MessageOut)
async def clear_openshell_gateway_credential(
    identity: TokenIdentity = Depends(require_api_auth),
    db: AsyncSession = Depends(get_db),
):
    await _require_admin(identity, db)
    from swarmer import openshell_oidc

    await openshell_oidc.clear_credential()
    return MessageOut(detail="OpenShell OIDC credential cleared.")


@router.post("/openshell-gateway/test", response_model=MessageOut)
async def test_openshell_gateway_connection(
    identity: TokenIdentity = Depends(require_api_auth),
    db: AsyncSession = Depends(get_db),
):
    """Exercise the configured gateway auth path with a plain Health RPC."""
    await _require_admin(identity, db)
    from swarmer import openshell_client
    from swarmer.config import settings

    if settings.openshell_auth_mode.lower() != "oidc":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"OPENSHELL_AUTH_MODE is '{settings.openshell_auth_mode}', not 'oidc' — "
                "set it (and redeploy) before testing the OIDC connection."
            ),
        )
    try:
        await openshell_client.health_check()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Connection test failed: {type(exc).__name__}: {exc}",
        ) from exc
    return MessageOut(detail="Connected to the OpenShell gateway successfully.")
