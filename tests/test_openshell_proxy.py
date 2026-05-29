"""
TDD tests for proxy/connectivity changes required by the OpenShell migration.

These tests are RED until ACM-34583 updates chat_proxy.py and tui_ws.py.

Validates:
  - chat_proxy.py no longer uses K8s Service DNS (.svc.cluster.local) for upstream
  - chat_proxy._session_ok() checks session.sandbox_name not session.pod_name
  - tui_ws.py no longer calls kubernetes.stream.stream() for exec
  - Server-mode sessions no longer create K8s ClusterIP Services or OpenShift Routes
"""
import sys
import os
import inspect
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# 1. chat_proxy: K8s Service DNS removed
# ---------------------------------------------------------------------------

def test_chat_proxy_not_using_k8s_service_dns():
    """After OpenShell migration, chat_proxy must not build upstream URLs using K8s Service DNS.

    Currently FAILS because _get_upstream_base() returns
    http://session-{id}-svc.{ns}.svc.cluster.local:{port}.
    Must pass after ACM-34583 replaces this with sandbox exec relay.
    """
    from swarmer.routers import chat_proxy
    source = inspect.getsource(chat_proxy)
    assert "svc.cluster.local" not in source, (
        "ACM-34583: Replace K8s Service DNS in chat_proxy._get_upstream_base() "
        "with OpenShell sandbox exec relay. "
        "Current code at swarmer/routers/chat_proxy.py line 38 must be removed."
    )


def test_chat_proxy_session_ok_uses_sandbox_name_not_pod_name():
    """After OpenShell migration, _session_ok() must accept sessions with sandbox_name (no pod).

    Currently FAILS because _session_ok() returns an error when pod_name is None.
    Must pass after ACM-34583 updates the check to use session.sandbox_name.
    """
    from swarmer.routers.chat_proxy import _session_ok

    ws_obj = MagicMock()
    session = MagicMock()
    session.workspace_id = 1
    session.mode = "server"
    session.is_active = True
    session.pod_name = None          # No K8s pod after OpenShell migration
    session.sandbox_name = "sandbox-s1-abc1"  # Has sandbox_name

    err = _session_ok(ws_obj, session, ws_id=1)
    assert err is None, (
        f"ACM-34583: _session_ok() must accept sessions with sandbox_name when pod_name is None. "
        f"Got error: {err!r}"
    )


def test_chat_proxy_websocket_not_using_k8s_service_dns():
    """WebSocket proxy in chat_proxy must also not use K8s Service DNS (directly or via _get_upstream_base)."""
    from swarmer.routers import chat_proxy
    source = inspect.getsource(chat_proxy.chat_ws_proxy)
    assert "svc.cluster.local" not in source and "_get_upstream_base" not in source, (
        "ACM-34583: chat_ws_proxy() still resolves upstream via K8s Service DNS "
        "(calls _get_upstream_base which builds .svc.cluster.local URLs). "
        "Replace with sandbox exec relay."
    )


# ---------------------------------------------------------------------------
# 2. tui_ws: kubernetes.stream removed
# ---------------------------------------------------------------------------

def test_tui_ws_not_using_kubernetes_stream():
    """After OpenShell migration, tui_ws must use SandboxClient.exec_stream(), not kubernetes.stream.

    Currently FAILS because session_tui() calls k8s_stream() at line 94.
    Must pass after ACM-34583 replaces it with openshell_client.exec_stream().
    """
    from swarmer.routers import tui_ws
    source = inspect.getsource(tui_ws)
    assert "k8s_stream(" not in source, (
        "ACM-34583: tui_ws.py still calls k8s_stream() (kubernetes.stream.stream). "
        "Replace with SandboxClient.exec_stream() from swarmer.openshell_client."
    )


def test_tui_ws_not_importing_kubernetes_stream():
    """tui_ws must not import kubernetes.stream after migration."""
    from swarmer.routers import tui_ws
    source = inspect.getsource(tui_ws)
    assert "from kubernetes.stream import" not in source, (
        "ACM-34583: tui_ws.py still imports from kubernetes.stream. "
        "Remove this import after replacing with SandboxClient.exec_stream()."
    )


def test_tui_ws_session_check_uses_sandbox_name():
    """tui_ws must check session.sandbox_name (not pod_name) for running state after migration."""
    from swarmer.routers import tui_ws
    source = inspect.getsource(tui_ws.session_tui)
    # After migration: sandbox_name replaces pod_name in the availability check
    assert "sandbox_name" in source, (
        "ACM-34583: session_tui() must check session.sandbox_name instead of session.pod_name."
    )


# ---------------------------------------------------------------------------
# 3. No K8s Service / Route creation for server-mode sessions
# ---------------------------------------------------------------------------

def test_sessions_router_not_calling_create_session_service():
    """_do_launch must not call create_session_service after OpenShell migration.

    Currently FAILS because _do_launch() creates a ClusterIP Service for server mode.
    Must pass after ACM-34583 removes that call (sandbox has its own network identity).
    """
    from swarmer.routers import sessions
    source = inspect.getsource(sessions._do_launch)
    assert "create_session_service" not in source, (
        "ACM-34583: _do_launch() still calls create_session_service(). "
        "OpenShell sandboxes have their own network identity — no K8s Service needed."
    )


def test_sessions_router_not_calling_create_session_route():
    """_do_launch must not call create_session_route after OpenShell migration."""
    from swarmer.routers import sessions
    source = inspect.getsource(sessions._do_launch)
    assert "create_session_route" not in source, (
        "ACM-34583: _do_launch() still calls create_session_route(). "
        "OpenShell sandboxes expose connectivity without OpenShift Routes."
    )
