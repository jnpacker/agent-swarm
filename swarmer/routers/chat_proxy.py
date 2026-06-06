"""
Reverse-proxy router for server-mode sessions.

Swarmer proxies HTTP/WebSocket traffic through /chat/{path} using
httpx + websockets, connecting to the session's ClusterIP Service via DNS.
HTML asset paths are rewritten so they resolve through the proxy prefix.
"""
import asyncio
import contextlib
import logging
import ssl

import httpx
import websockets
from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from swarmer.database import get_db
from swarmer.deps import require_auth
from swarmer.models.session import Session
from swarmer.models.workspace import Workspace

router = APIRouter()
log = logging.getLogger(__name__)
templates = Jinja2Templates(directory="swarmer/templates")

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
})

# ── OpenShell mTLS helpers ────────────────────────────────────────────────────

def _openshell_ssl_context() -> ssl.SSLContext | None:
    """Return an SSL context with the OpenShell client cert, or None for plain HTTP."""
    from swarmer.config import settings
    cert = settings.openshell_tls_cert
    key = settings.openshell_tls_key
    if not cert or not key:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # gateway uses self-signed cert
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def _openshell_httpx_kwargs() -> dict:
    """Return httpx kwargs for connecting to an OpenShell gateway service URL."""
    from swarmer.config import settings
    cert = settings.openshell_tls_cert
    key = settings.openshell_tls_key
    if cert and key:
        return {"verify": False, "cert": (cert, key)}
    return {"verify": False}


# ── Upstream URL resolution ───────────────────────────────────────────────────

def _get_upstream_base(session_id: int, namespace: str, remote_port: int = 4096) -> str:
    """Return the ClusterIP Service base URL for the session's agent process."""
    svc = f"session-{session_id}-svc"
    return f"http://{svc}.{namespace}.svc.cluster.local:{remote_port}"


# ── HTML rewriting (in-cluster only) ─────────────────────────────────────────

def _rewrite_html(content: bytes, prefix: str) -> bytes:
    """Rewrite absolute asset paths in HTML so they resolve through the proxy."""
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return content

    base_tag = f'<base href="{prefix}/">'
    if "<head>" in text:
        text = text.replace("<head>", f"<head>{base_tag}", 1)
    elif "<HEAD>" in text:
        text = text.replace("<HEAD>", f"<HEAD>{base_tag}", 1)

    for old, new in [
        ('src="/',    f'src="{prefix}/'),
        ("src='/",    f"src='{prefix}/"),
        ('href="/',   f'href="{prefix}/'),
        ("href='/",   f"href='{prefix}/"),
        ('action="/', f'action="{prefix}/'),
    ]:
        text = text.replace(old, new)

    return text.encode("utf-8")


# ── Session lookup helper ─────────────────────────────────────────────────────

async def _load(ws_id: int, sid: int, db: AsyncSession):
    ws_obj = await db.get(Workspace, ws_id)
    session = await db.get(Session, sid)
    return ws_obj, session


def _session_ok(ws_obj, session, ws_id: int) -> str | None:
    """Return an error string if the session can't be proxied, else None."""
    if ws_obj is None or session is None or session.workspace_id != ws_id:
        return "Not found"
    if session.mode != "server" or not session.is_active:
        return "Session is not running in server mode"
    if not session.pod_name and not session.service_url:
        return "Session is not running in server mode"
    return None


# ── Entry point: /chat (no trailing slash) ────────────────────────────────────

async def _proxy_root(
    ws_id: int,
    sid: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Response:
    ws_obj, session = await _load(ws_id, sid, db)
    err = _session_ok(ws_obj, session, ws_id)
    if err:
        return Response(err, status_code=503 if "running" in err else 404, media_type="text/plain")

    from swarmer.k8s import effective_namespace
    namespace = effective_namespace(ws_obj.k8s_namespace)

    # Crush sessions: serve the built-in chat UI (swarmer renders the page,
    # the JS inside makes API calls through the /chat/{path} proxy).
    if session.agent_tool == "crush":
        return templates.TemplateResponse(
            request,
            "sessions/crush_chat.html",
            {
                "ws": ws_obj,
                "session": session,
                "model_name": session.model.split("/")[-1] if session.model else "default",
                "provider_name": session.model.split("/")[0] if "/" in session.model else "default",
            },
        )

    # Use the OpenShift Route if one exists — the browser connects directly to
    # opencode with no sub-path mangling.
    from swarmer.k8s import get_session_route_host
    host = get_session_route_host(session.id, namespace)
    if host:
        return RedirectResponse(url=f"https://{host}/", status_code=302)

    # Fallback: sub-path HTTP proxy (works for HTTP assets, not ideal for WebSockets).
    return RedirectResponse(
        url=f"/workspaces/{ws_id}/sessions/{sid}/chat/",
        status_code=302,
    )


# ── Sub-path proxy (in-cluster) ───────────────────────────────────────────────

async def _chat_http_proxy(
    ws_id: int,
    sid: int,
    request: Request,
    path: str,
    db: AsyncSession,
) -> Response:
    from starlette.responses import StreamingResponse

    ws_obj, session = await _load(ws_id, sid, db)
    err = _session_ok(ws_obj, session, ws_id)
    if err:
        return Response(err, status_code=503 if "running" in err else 404, media_type="text/plain")

    if session.service_url:
        upstream_base = session.service_url.rstrip("/")
    else:
        from swarmer.k8s import effective_namespace
        namespace = effective_namespace(ws_obj.k8s_namespace)
        try:
            upstream_base = _get_upstream_base(session.id, namespace)
        except Exception as exc:
            log.warning("Could not connect to session %d: %s", sid, exc)
            return Response(f"Could not connect to session: {exc}", status_code=503, media_type="text/plain")

    query = str(request.url.query)
    upstream_url = f"{upstream_base}/{path}"
    if query:
        upstream_url += f"?{query}"

    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
    fwd_headers["x-opencode-directory"] = "/sandbox/" if session.sandbox_name else "/workspace"

    # Check if the request wants SSE (event-stream)
    accept = request.headers.get("accept", "")
    is_sse = "text/event-stream" in accept or "/events" in path

    _tls_kwargs = _openshell_httpx_kwargs() if session.sandbox_name else {}

    if is_sse:
        # Stream SSE responses — long-lived connection, no timeout buffering
        client = httpx.AsyncClient(**_tls_kwargs, timeout=httpx.Timeout(connect=10, read=None, write=10, pool=10))

        async def sse_generator():
            try:
                async with client.stream(
                    "GET",
                    upstream_url,
                    headers=fwd_headers,
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk
            except Exception as exc:
                log.warning("SSE stream error for session %d: %s", sid, exc)
            finally:
                await client.aclose()

        return StreamingResponse(
            sse_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # Standard request/response proxy
    try:
        async with httpx.AsyncClient(**_tls_kwargs) as client:
            upstream_resp = await client.request(
                method=request.method,
                url=upstream_url,
                headers=fwd_headers,
                content=await request.body(),
                follow_redirects=False,
                timeout=30.0,
            )
    except Exception as exc:
        log.warning("chat proxy: upstream error %s for session %d url=%s: %s",
                    type(exc).__name__, sid, upstream_url, exc, exc_info=True)
        return Response(
            f"Could not connect to session ({upstream_base}): {type(exc).__name__}: {exc}",
            status_code=503, media_type="text/plain",
        )

    content_type = upstream_resp.headers.get("content-type", "")
    content = upstream_resp.content

    if "text/html" in content_type:
        prefix = f"/workspaces/{ws_id}/sessions/{sid}/chat"
        content = _rewrite_html(content, prefix)

    resp_headers = {k: v for k, v in upstream_resp.headers.items() if k.lower() not in _HOP_BY_HOP}
    resp_headers.pop("content-length", None)

    return Response(
        content=content,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=content_type or None,
    )


async def _proxy_path(
    ws_id: int,
    sid: int,
    path: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Response:
    return await _chat_http_proxy(ws_id, sid, request, path, db)


_PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

router.add_api_route(
    "/workspaces/{ws_id}/sessions/{sid}/chat",
    _proxy_root,
    methods=_PROXY_METHODS,
    dependencies=[Depends(require_auth)],
)
router.add_api_route(
    "/workspaces/{ws_id}/sessions/{sid}/chat/{path:path}",
    _proxy_path,
    methods=_PROXY_METHODS,
    dependencies=[Depends(require_auth)],
)


# ── WebSocket proxy ───────────────────────────────────────────────────────────

@router.websocket("/workspaces/{ws_id}/sessions/{sid}/chat/{path:path}")
async def chat_ws_proxy(
    websocket: WebSocket,
    ws_id: int,
    sid: int,
    path: str,
):
    await websocket.accept()

    if not websocket.session.get("authenticated"):
        await websocket.close(code=4001, reason="Not authenticated")
        return

    async for db in get_db():
        ws_obj = await db.get(Workspace, ws_id)
        session = await db.get(Session, sid)
        break

    if (
        ws_obj is None
        or session is None
        or session.workspace_id != ws_id
        or session.mode != "server"
        or not session.is_active
        or (not session.pod_name and not session.service_url)
    ):
        await websocket.close(code=4004, reason="Session unavailable")
        return

    if session.service_url:
        upstream_base = session.service_url.rstrip("/")
    else:
        from swarmer.k8s import effective_namespace
        namespace = effective_namespace(ws_obj.k8s_namespace)
        try:
            upstream_base = _get_upstream_base(session.id, namespace)
        except Exception as exc:
            log.warning("Could not connect to session %d for WS: %s", sid, exc)
            await websocket.close(code=4004, reason="Could not connect to session")
            return

    query = websocket.url.query
    upstream_url = upstream_base.replace("http://", "ws://").replace("https://", "wss://") + f"/{path}"
    if query:
        upstream_url += f"?{query}"

    _ws_ssl = _openshell_ssl_context() if session.sandbox_name and upstream_url.startswith("wss://") else None

    try:
        async with websockets.connect(upstream_url, ssl=_ws_ssl) as upstream_ws:
            async def client_to_upstream() -> None:
                try:
                    while True:
                        data = await websocket.receive()
                        if "text" in data:
                            await upstream_ws.send(data["text"])
                        elif "bytes" in data:
                            await upstream_ws.send(data["bytes"])
                except (WebSocketDisconnect, Exception):
                    pass

            async def upstream_to_client() -> None:
                try:
                    async for message in upstream_ws:
                        if isinstance(message, bytes):
                            await websocket.send_bytes(message)
                        else:
                            await websocket.send_text(message)
                except Exception:
                    pass

            tasks = [
                asyncio.create_task(client_to_upstream()),
                asyncio.create_task(upstream_to_client()),
            ]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    except Exception as exc:
        log.warning("Chat WS proxy error for session %d: %s", sid, exc)
    finally:
        with contextlib.suppress(Exception):
            await websocket.close()
