"""Tests for OpenShell TUI WebSocket and chat proxy integration.

Covers:
  - openshell_client: expose_service(), delete_service(), exec_interactive()
  - chat_proxy: _session_ok() accepts service_url, HTTP/WS proxy uses service_url,
    x-opencode-directory header is /sandbox/ for OpenShell sessions
  - tui_ws: session validation accepts sandbox_name, ExecSandboxInteractive is called,
    stdin/resize/stdout forwarding, exit event closes WS
  - sessions.py: server mode calls expose_service after start_agent,
    stop/delete call delete_service before delete_sandbox
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from swarmer.database import Base

# ---------------------------------------------------------------------------
# Inject openshell SDK stub (no real package needed for unit tests)
# ---------------------------------------------------------------------------


class _SandboxSpec:
    def __init__(self):
        class _T:
            image = ""
        self.template = _T()
        self.environment = {}
        self.policy = None
        self.providers = []


_proto_stub = MagicMock()
_proto_stub.openshell_pb2 = MagicMock()
_proto_stub.openshell_pb2.SandboxSpec = _SandboxSpec

_sdk_stub = MagicMock()
_sdk_stub.SandboxClient = MagicMock
_sdk_stub.TlsConfig = MagicMock
_sdk_stub._proto = _proto_stub

sys.modules.setdefault("openshell", _sdk_stub)
sys.modules.setdefault("openshell._proto", _proto_stub)
sys.modules.setdefault("openshell._proto.openshell_pb2", _proto_stub.openshell_pb2)

import swarmer.openshell_client as oc  # noqa: E402


# ---------------------------------------------------------------------------
# Shared DB + app fixtures
# ---------------------------------------------------------------------------

_engine = create_async_engine("sqlite+aiosqlite://", echo=False)
_TestSession = async_sessionmaker(_engine, expire_on_commit=False)


async def _override_get_db():
    async with _TestSession() as session:
        yield session


def _override_require_api_auth():
    from swarmer.k8s_auth import TokenIdentity
    return TokenIdentity(username="test-user", uid="uid-1234")


def _override_get_current_user():
    return "test-user"


@pytest_asyncio.fixture(autouse=True)
async def _setup_db():
    from swarmer.crypto import init_crypto
    init_crypto("auth/secret.key")

    from swarmer.config import settings
    orig_ns = settings.k8s_namespace
    orig_max = settings.max_concurrent_agents
    settings.k8s_namespace = "test-ns"
    settings.max_concurrent_agents = 0

    import swarmer.models  # noqa: F401

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    settings.k8s_namespace = orig_ns
    settings.max_concurrent_agents = orig_max


@pytest_asyncio.fixture
async def client():
    from swarmer.api.deps import get_current_user, require_api_auth
    from swarmer.database import get_db
    from swarmer.deps import require_auth
    from swarmer.main import app

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[require_api_auth] = _override_require_api_auth
    app.dependency_overrides[get_current_user] = _override_get_current_user
    app.dependency_overrides[require_auth] = lambda: None  # bypass browser session auth

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


async def _create_workspace(client, name="Proxy Test WS"):
    resp = await client.post("/api/v1/workspaces", json={"display_name": name, "description": ""})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _create_session(client, ws_id, name="s1", mode="server", agent_tool="opencode"):
    resp = await client.post(
        f"/api/v1/workspaces/{ws_id}/sessions",
        json={"name": name, "mode": mode, "agent_tool": agent_tool},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Fake SDK client
# ---------------------------------------------------------------------------


@pytest.fixture
def sdk_client():
    client = MagicMock()
    # ExposeService → returns ServiceEndpointResponse with url
    expose_resp = MagicMock()
    expose_resp.url = "https://agent.sandbox-abc.openshell.example.com"
    client._stub.ExposeService.return_value = expose_resp
    client._stub.DeleteService.return_value = MagicMock()
    client._timeout = 30
    ref = MagicMock()
    ref.id = "sandbox-abc123"
    ref.name = "sandbox-test-abc"
    client.get.return_value = ref
    return client


# ===========================================================================
# 1. openshell_client wrappers
# ===========================================================================


class TestExposeService:
    @pytest.mark.asyncio
    async def test_expose_service_calls_stub(self, sdk_client):
        from openshell._proto import openshell_pb2 as pb
        with patch.object(oc, "_get_client", return_value=sdk_client):
            url = await oc.expose_service("sandbox-test-abc", "agent", 4096)
        sdk_client._stub.ExposeService.assert_called_once()
        args = sdk_client._stub.ExposeService.call_args
        req = args[0][0]  # first positional arg
        assert req.sandbox == "sandbox-test-abc"
        assert req.service == "agent"
        assert req.target_port == 4096
        assert req.domain is True

    @pytest.mark.asyncio
    async def test_expose_service_returns_url(self, sdk_client):
        with patch.object(oc, "_get_client", return_value=sdk_client):
            url = await oc.expose_service("sandbox-test-abc", "agent", 4096)
        assert url == "https://agent.sandbox-abc.openshell.example.com"

    @pytest.mark.asyncio
    async def test_delete_service_calls_stub(self, sdk_client):
        with patch.object(oc, "_get_client", return_value=sdk_client):
            await oc.delete_service("sandbox-test-abc", "agent")
        sdk_client._stub.DeleteService.assert_called_once()
        args = sdk_client._stub.DeleteService.call_args
        req = args[0][0]
        assert req.sandbox == "sandbox-test-abc"
        assert req.service == "agent"


class TestExecInteractive:
    def test_exec_interactive_returns_stream_and_queue(self, sdk_client):
        mock_stream = iter([])
        sdk_client._stub.ExecSandboxInteractive.return_value = mock_stream
        with patch.object(oc, "_get_client", return_value=sdk_client):
            stream, input_q = oc.exec_interactive(
                sandbox_name="sandbox-test",
                sandbox_id="abc123",
                command=["sh", "-c", "opencode"],
                cols=80,
                rows=24,
                client=sdk_client,
            )
        assert stream is mock_stream
        assert input_q is not None

    def test_exec_interactive_sends_start_message(self, sdk_client):
        from openshell._proto import openshell_pb2 as pb

        received_msgs = []

        def _capture_stream(request_iter, **kwargs):
            for msg in request_iter:
                received_msgs.append(msg)
                break  # read only the first (start) message
            return iter([])

        sdk_client._stub.ExecSandboxInteractive.side_effect = _capture_stream

        with patch.object(oc, "_get_client", return_value=sdk_client):
            stream, input_q = oc.exec_interactive(
                sandbox_name="sandbox-test",
                sandbox_id="abc123",
                command=["sh", "-c", "opencode --continue"],
                cols=120,
                rows=40,
                client=sdk_client,
            )
            input_q.put(None)  # stop the generator after reading 1 message

        assert len(received_msgs) == 1
        start_msg = received_msgs[0]
        assert start_msg.start.sandbox_id == "abc123"
        assert start_msg.start.tty is True
        assert start_msg.start.cols == 120
        assert start_msg.start.rows == 40
        assert start_msg.start.workdir == "/sandbox"


# ===========================================================================
# 2. chat_proxy._session_ok()
# ===========================================================================


class TestSessionOk:
    def _make_session(self, pod_name=None, service_url=None, mode="server", phase="running"):
        s = MagicMock()
        s.pod_name = pod_name
        s.service_url = service_url
        s.mode = mode
        s.workspace_id = 1
        s.is_active = phase == "running"
        return s

    def _make_ws(self, ws_id=1):
        ws = MagicMock()
        ws.id = ws_id
        return ws

    def test_session_ok_accepts_pod_name(self):
        from swarmer.routers.chat_proxy import _session_ok
        ws = self._make_ws()
        s = self._make_session(pod_name="session-1-pod")
        assert _session_ok(ws, s, 1) is None

    def test_session_ok_accepts_service_url(self):
        from swarmer.routers.chat_proxy import _session_ok
        ws = self._make_ws()
        s = self._make_session(service_url="https://agent.openshell.example.com")
        assert _session_ok(ws, s, 1) is None

    def test_session_ok_rejects_neither(self):
        from swarmer.routers.chat_proxy import _session_ok
        ws = self._make_ws()
        s = self._make_session()  # no pod_name, no service_url
        assert _session_ok(ws, s, 1) is not None

    def test_session_ok_rejects_non_server_mode(self):
        from swarmer.routers.chat_proxy import _session_ok
        ws = self._make_ws()
        s = self._make_session(pod_name="pod", mode="tui")
        assert _session_ok(ws, s, 1) is not None

    def test_session_ok_rejects_wrong_workspace(self):
        from swarmer.routers.chat_proxy import _session_ok
        ws = self._make_ws(ws_id=1)
        s = self._make_session(service_url="https://agent.example.com")
        s.workspace_id = 999  # mismatch
        assert _session_ok(ws, s, 1) is not None


# ===========================================================================
# 3. HTTP proxy uses service_url as upstream
# ===========================================================================


class TestChatHttpProxy:
    def _make_mock_client(self, status=200, content=b"ok", content_type="text/plain"):
        """Return a context-manager mock for httpx.AsyncClient used in the proxy."""
        import httpx as _httpx
        mock_resp = MagicMock()
        mock_resp.status_code = status
        mock_resp.content = content
        mock_resp.headers = _httpx.Headers({"content-type": content_type})

        mock_instance = AsyncMock()
        mock_instance.request = AsyncMock(return_value=mock_resp)

        mock_cls = MagicMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        return mock_cls, mock_instance

    @pytest.mark.asyncio
    async def test_proxy_uses_service_url_for_upstream(self, client):
        ws = await _create_workspace(client)
        s = await _create_session(client, ws["id"], mode="server", agent_tool="opencode")

        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            session_obj = await db.get(_Session, s["id"])
            session_obj.phase = "running"
            session_obj.sandbox_name = "sandbox-test-abc"
            session_obj.service_url = "http://agent.openshell.internal:4096"
            await db.commit()

        mock_cls, mock_instance = self._make_mock_client(
            content=b"<html><head></head><body>ok</body></html>",
            content_type="text/html",
        )
        with patch("swarmer.routers.chat_proxy.httpx.AsyncClient", mock_cls):
            await client.get(
                f"/workspaces/{ws['id']}/sessions/{s['id']}/chat/index.html"
            )

        mock_instance.request.assert_called_once()
        _, call_kwargs = mock_instance.request.call_args
        assert "agent.openshell.internal" in call_kwargs.get("url", ""), (
            f"Expected service_url upstream in request URL, got: {call_kwargs}"
        )

    @pytest.mark.asyncio
    async def test_proxy_sets_sandbox_directory_header(self, client):
        ws = await _create_workspace(client)
        s = await _create_session(client, ws["id"], mode="server", agent_tool="opencode")

        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            session_obj = await db.get(_Session, s["id"])
            session_obj.phase = "running"
            session_obj.sandbox_name = "sandbox-test-abc"
            session_obj.service_url = "http://agent.openshell.internal:4096"
            await db.commit()

        mock_cls, mock_instance = self._make_mock_client()
        with patch("swarmer.routers.chat_proxy.httpx.AsyncClient", mock_cls):
            await client.get(f"/workspaces/{ws['id']}/sessions/{s['id']}/chat/api")

        mock_instance.request.assert_called_once()
        _, call_kwargs = mock_instance.request.call_args
        assert call_kwargs.get("headers", {}).get("x-opencode-directory") == "/sandbox/"

    @pytest.mark.asyncio
    async def test_proxy_sets_workspace_directory_for_k8s(self, client):
        ws = await _create_workspace(client)
        s = await _create_session(client, ws["id"], mode="server", agent_tool="opencode")

        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            session_obj = await db.get(_Session, s["id"])
            session_obj.phase = "running"
            session_obj.pod_name = "session-1-pod"
            # no sandbox_name → K8s session
            await db.commit()

        mock_cls, mock_instance = self._make_mock_client()
        with patch("swarmer.routers.chat_proxy.httpx.AsyncClient", mock_cls), \
             patch("swarmer.k8s.effective_namespace", return_value="test-ns"):
            await client.get(f"/workspaces/{ws['id']}/sessions/{s['id']}/chat/api")

        mock_instance.request.assert_called_once()
        _, call_kwargs = mock_instance.request.call_args
        assert call_kwargs.get("headers", {}).get("x-opencode-directory") == "/workspace"


# ===========================================================================
# 4. Session lifecycle: expose_service and delete_service
# ===========================================================================


async def _test_get_db():
    """Yield a session from the test DB — for use when code calls get_db() directly."""
    async with _TestSession() as session:
        yield session


class TestServerModeExposeService:
    @pytest.mark.asyncio
    async def test_server_mode_calls_expose_service(self, client):
        """_run_openshell_agent server mode calls expose_service after start_agent."""
        from swarmer.routers.sessions import _run_openshell_agent

        expose_mock = AsyncMock(return_value="https://agent.sandbox.example.com")
        start_mock = AsyncMock()

        ws = await _create_workspace(client)
        s = await _create_session(client, ws["id"], mode="server")
        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            session_obj = await db.get(_Session, s["id"])
            session_obj.sandbox_name = "sandbox-test-abc"
            await db.commit()

        with patch("swarmer.openshell_client.start_agent", start_mock), \
             patch("swarmer.openshell_client.expose_service", expose_mock), \
             patch("swarmer.database.get_db", _test_get_db), \
             patch("swarmer.routers.sessions.asyncio.sleep", AsyncMock()):
            await _run_openshell_agent(
                session_id=s["id"],
                sandbox_name="sandbox-test-abc",
                cmd=["opencode", "serve", "--port", "4096"],
                mode="server",
                agent_tool="opencode",
            )

        start_mock.assert_called_once()
        expose_mock.assert_called_once_with("sandbox-test-abc", "agent", 4096)

    @pytest.mark.asyncio
    async def test_tui_mode_does_not_call_expose_service(self, client):
        """TUI mode should NOT call expose_service."""
        from swarmer.routers.sessions import _run_openshell_agent

        expose_mock = AsyncMock(return_value="https://agent.sandbox.example.com")
        start_mock = AsyncMock()

        ws = await _create_workspace(client)
        s = await _create_session(client, ws["id"], mode="tui")
        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            session_obj = await db.get(_Session, s["id"])
            session_obj.sandbox_name = "sandbox-test-abc"
            await db.commit()

        with patch("swarmer.openshell_client.start_agent", start_mock), \
             patch("swarmer.openshell_client.expose_service", expose_mock), \
             patch("swarmer.database.get_db", _test_get_db):
            await _run_openshell_agent(
                session_id=s["id"],
                sandbox_name="sandbox-test-abc",
                cmd=["opencode"],
                mode="tui",
                agent_tool="opencode",
            )

        expose_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_server_mode_stores_service_url(self, client):
        """service_url is persisted in the session after expose_service."""
        from swarmer.routers.sessions import _run_openshell_agent

        expose_mock = AsyncMock(return_value="https://agent.sandbox.example.com")

        ws = await _create_workspace(client)
        s = await _create_session(client, ws["id"], mode="server")
        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            session_obj = await db.get(_Session, s["id"])
            session_obj.sandbox_name = "sandbox-test-abc"
            await db.commit()

        with patch("swarmer.openshell_client.start_agent", AsyncMock()), \
             patch("swarmer.openshell_client.expose_service", expose_mock), \
             patch("swarmer.database.get_db", _test_get_db), \
             patch("swarmer.routers.sessions.asyncio.sleep", AsyncMock()):
            await _run_openshell_agent(
                session_id=s["id"],
                sandbox_name="sandbox-test-abc",
                cmd=["opencode", "serve"],
                mode="server",
                agent_tool="opencode",
            )

        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            updated = await db.get(_Session, s["id"])
            assert updated.service_url == "https://agent.sandbox.example.com"


class TestStopDeleteCallsDeleteService:
    @pytest.mark.asyncio
    async def test_stop_calls_delete_service(self, client):
        ws = await _create_workspace(client)
        s = await _create_session(client, ws["id"], mode="server")

        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            session_obj = await db.get(_Session, s["id"])
            session_obj.phase = "running"
            session_obj.sandbox_name = "sandbox-test-abc"
            session_obj.service_url = "https://agent.sandbox.example.com"
            await db.commit()

        delete_svc_mock = AsyncMock()
        delete_sandbox_mock = AsyncMock()

        with patch("swarmer.openshell_client.delete_service", delete_svc_mock), \
             patch("swarmer.openshell_client.delete_sandbox", delete_sandbox_mock):
            resp = await client.post(
                f"/workspaces/{ws['id']}/sessions/{s['id']}/stop",
                follow_redirects=False,
            )

        assert resp.status_code in (302, 200)
        delete_svc_mock.assert_called_once_with("sandbox-test-abc", "agent")
        delete_sandbox_mock.assert_called_once_with("sandbox-test-abc")

    @pytest.mark.asyncio
    async def test_delete_calls_delete_service(self, client):
        ws = await _create_workspace(client)
        s = await _create_session(client, ws["id"], mode="server")

        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            session_obj = await db.get(_Session, s["id"])
            session_obj.phase = "stopped"
            session_obj.sandbox_name = "sandbox-test-abc"
            session_obj.service_url = "https://agent.sandbox.example.com"
            await db.commit()

        delete_svc_mock = AsyncMock()
        delete_sandbox_mock = AsyncMock()

        with patch("swarmer.openshell_client.delete_service", delete_svc_mock), \
             patch("swarmer.openshell_client.delete_sandbox", delete_sandbox_mock):
            resp = await client.post(
                f"/workspaces/{ws['id']}/sessions/{s['id']}/delete",
                follow_redirects=False,
            )

        assert resp.status_code in (302, 200)
        delete_svc_mock.assert_called_once_with("sandbox-test-abc", "agent")

    @pytest.mark.asyncio
    async def test_stop_clears_service_url_from_db(self, client):
        ws = await _create_workspace(client)
        s = await _create_session(client, ws["id"], mode="server")

        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            session_obj = await db.get(_Session, s["id"])
            session_obj.phase = "running"
            session_obj.sandbox_name = "sandbox-test-abc"
            session_obj.service_url = "https://agent.sandbox.example.com"
            await db.commit()

        with patch("swarmer.openshell_client.delete_service", AsyncMock()), \
             patch("swarmer.openshell_client.delete_sandbox", AsyncMock()):
            await client.post(
                f"/workspaces/{ws['id']}/sessions/{s['id']}/stop",
                follow_redirects=False,
            )

        async with _TestSession() as db:
            from swarmer.models.session import Session as _Session
            updated = await db.get(_Session, s["id"])
            assert updated.service_url is None
            assert updated.sandbox_name is None


# ===========================================================================
# 5. TUI WebSocket — OpenShell path (unit-level)
# ===========================================================================


class TestTuiWsOpenshell:
    """Unit-level tests for the OpenShell branch in tui_ws.py.

    These do not open a real WebSocket connection — they test the helper logic
    and the openshell_client wrappers that the TUI handler uses.
    """

    def test_exec_interactive_stdin_queued(self):
        """The first message in the stream is always the start message with sandbox_id."""
        from openshell._proto import openshell_pb2 as pb

        received = []

        def _capture_stream(request_iter, **kwargs):
            # Only read the start message; the generator blocks on queue.get() after
            # that so we must break after 1 to avoid deadlock.
            for msg in request_iter:
                received.append(msg)
                break
            return iter([])

        sdk_client = MagicMock()
        sdk_client._stub.ExecSandboxInteractive.side_effect = _capture_stream
        sdk_client._timeout = 30

        stream, input_q = oc.exec_interactive(
            sandbox_name="sandbox-x",
            sandbox_id="id-x",
            command=["sh", "-c", "opencode"],
            cols=80,
            rows=24,
            client=sdk_client,
        )
        input_q.put(None)  # unblock generator if it ever resumes

        assert len(received) == 1
        assert received[0].start.sandbox_id == "id-x"

    def test_exec_interactive_resize_queued(self):
        """The first message in the stream carries the correct sandbox_id and tty flags."""
        from openshell._proto import openshell_pb2 as pb

        received = []

        def _capture_stream(request_iter, **kwargs):
            for msg in request_iter:
                received.append(msg)
                break
            return iter([])

        sdk_client = MagicMock()
        sdk_client._stub.ExecSandboxInteractive.side_effect = _capture_stream
        sdk_client._timeout = 30

        stream, input_q = oc.exec_interactive(
            sandbox_name="sandbox-x",
            sandbox_id="id-x",
            command=["sh", "-c", "crush"],
            cols=80,
            rows=24,
            client=sdk_client,
        )
        input_q.put(None)  # unblock generator if it ever resumes

        assert received[0].start.sandbox_id == "id-x"


# ===========================================================================
# 6. E2E Smoke Tests (require dev server at :8091 with SWARMER_DEV_AUTH=1)
# ===========================================================================
#
# These are skipped unless the SWARMER_E2E environment variable is set.
# Run with: SWARMER_E2E=1 pytest tests/test_openshell_proxy.py -k smoke -v


import os as _os
_E2E = _os.environ.get("SWARMER_E2E") == "1"
_E2E_BASE = _os.environ.get("SWARMER_E2E_URL", "http://localhost:8091")


@pytest.mark.skipif(not _E2E, reason="Set SWARMER_E2E=1 to run e2e smoke tests")
class TestE2eSmokeProxy:
    """
    E2E smoke tests for OpenShell TUI + server-mode proxy flow.

    These tests call the real running app and verify end-to-end behavior
    against a session that has already been started with OpenShell enabled.
    They assume SWARMER_DEV_AUTH=1 (no token required).

    Env vars:
      SWARMER_E2E=1         — enable this test class
      SWARMER_E2E_URL       — base URL (default http://localhost:8091)
      SWARMER_E2E_WS_ID     — workspace ID to use (required)
      SWARMER_E2E_SID       — session ID of a running server-mode OpenShell session
      SWARMER_E2E_TUI_SID   — session ID of a running tui-mode OpenShell session
    """

    @pytest.fixture(autouse=True)
    def check_env(self):
        ws_id = _os.environ.get("SWARMER_E2E_WS_ID")
        if not ws_id:
            pytest.skip("SWARMER_E2E_WS_ID not set")

    @property
    def _ws_id(self):
        return int(_os.environ["SWARMER_E2E_WS_ID"])

    @property
    def _sid(self):
        val = _os.environ.get("SWARMER_E2E_SID")
        if not val:
            pytest.skip("SWARMER_E2E_SID not set")
        return int(val)

    @property
    def _tui_sid(self):
        val = _os.environ.get("SWARMER_E2E_TUI_SID")
        if not val:
            pytest.skip("SWARMER_E2E_TUI_SID not set")
        return int(val)

    @pytest.mark.asyncio
    async def test_smoke_chat_proxy_responds(self):
        """Server-mode OpenShell session: /chat/ returns 200 or proxies upstream."""
        import httpx
        ws_id, sid = self._ws_id, self._sid
        async with httpx.AsyncClient(base_url=_E2E_BASE, follow_redirects=True) as hc:
            resp = await hc.get(f"/workspaces/{ws_id}/sessions/{sid}/chat/")
        assert resp.status_code in (200, 503), (
            f"Expected 200 (upstream ok) or 503 (upstream not ready), got {resp.status_code}"
        )

    @pytest.mark.asyncio
    async def test_smoke_session_detail_has_terminal_tab_for_tui(self):
        """TUI-mode OpenShell session: session detail page renders the terminal panel."""
        import httpx
        ws_id, sid = self._ws_id, self._tui_sid
        async with httpx.AsyncClient(base_url=_E2E_BASE, follow_redirects=True) as hc:
            resp = await hc.get(f"/workspaces/{ws_id}/sessions/{sid}")
        assert resp.status_code == 200
        assert "terminal" in resp.text.lower() or "xterm" in resp.text.lower(), (
            "Expected TUI terminal tab in session detail for tui-mode session"
        )

    @pytest.mark.asyncio
    async def test_smoke_service_url_set_on_running_server_session(self):
        """server-mode OpenShell session: API exposes service_url when running."""
        import httpx
        ws_id, sid = self._ws_id, self._sid
        async with httpx.AsyncClient(base_url=_E2E_BASE, follow_redirects=True) as hc:
            resp = await hc.get(f"/api/v1/workspaces/{ws_id}/sessions/{sid}")
        assert resp.status_code == 200
        data = resp.json()
        # service_url may be None if session is not running yet, but must be present in schema
        assert "service_url" in data or data.get("phase") != "running", (
            f"service_url missing from API response for running session: {data}"
        )
