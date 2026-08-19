"""Console routes — OpenShell Gateway admin config page (ACM-41655).

Lets a Swarmer admin seed/rotate the encrypted OIDC refresh token used to
connect to a remote/hosted OpenShell gateway (e.g. the "swarm" gateway)
directly from the dashboard, instead of `kubectl exec`-ing
scripts/openshell_seed_oidc_credential.py into the pod (see
`make openshell-oidc-seed`, still available for headless/CI use).

All data access goes through the REST API client (/api/v1/), consistent with
the rest of the console (see swarmer/routers/admins.py).
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from swarmer.deps import require_auth
from swarmer.flash import flash
from swarmer.routers.api_client import APIError, get_api_client

router = APIRouter()
templates = Jinja2Templates(directory="swarmer/templates")


@router.get("/admin/openshell-gateway", dependencies=[Depends(require_auth)])
async def openshell_gateway_status(request: Request):
    async with get_api_client(request) as api:
        try:
            me = await api.get_me()
        except APIError:
            me = {}

        status_data = {}
        if me.get("is_admin"):
            try:
                status_data = await api.get_openshell_gateway_status()
            except APIError as exc:
                flash(request, f"Failed to load gateway status: {exc.detail}", "danger")

    return templates.TemplateResponse(
        request,
        "admin_openshell_gateway/status.html",
        {
            "is_admin": me.get("is_admin", False),
            "status": status_data,
        },
    )


@router.post("/admin/openshell-gateway/credential", dependencies=[Depends(require_auth)])
async def openshell_gateway_save_credential(request: Request, refresh_token: str = Form(...)):
    async with get_api_client(request) as api:
        try:
            await api.set_openshell_gateway_credential(refresh_token.strip())
            flash(request, "OpenShell OIDC credential saved.", "success")
        except APIError as exc:
            flash(request, f"Failed to save credential: {exc.detail}", "danger")

    return RedirectResponse(url="/admin/openshell-gateway", status_code=302)


@router.post("/admin/openshell-gateway/clear", dependencies=[Depends(require_auth)])
async def openshell_gateway_clear_credential(request: Request):
    async with get_api_client(request) as api:
        try:
            await api.clear_openshell_gateway_credential()
            flash(request, "OpenShell OIDC credential cleared.", "success")
        except APIError as exc:
            flash(request, f"Failed to clear credential: {exc.detail}", "danger")

    return RedirectResponse(url="/admin/openshell-gateway", status_code=302)


@router.post("/admin/openshell-gateway/test", dependencies=[Depends(require_auth)])
async def openshell_gateway_test_connection(request: Request):
    async with get_api_client(request) as api:
        try:
            result = await api.test_openshell_gateway_connection()
            flash(request, result.get("detail", "Connection test succeeded."), "success")
        except APIError as exc:
            flash(request, f"Connection test failed: {exc.detail}", "danger")

    return RedirectResponse(url="/admin/openshell-gateway", status_code=302)
