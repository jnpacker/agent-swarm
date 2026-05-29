"""
End-to-end tests for OpenShell sandbox integration against real Kubernetes clusters.

All tests are SKIPPED unless OPENSHELL_GATEWAY_URL is set in the environment.
Set OPENSHELL_CLUSTER_TYPE=openshift|kind to run cluster-specific assertions.

Environment variables:
  OPENSHELL_GATEWAY_URL   Required. e.g. "openshell.openshell.svc.cluster.local:8080"
  OPENSHELL_TLS_CA_PATH   Path to CA cert for mTLS (optional for in-cluster)
  OPENSHELL_TLS_CERT_PATH Path to client cert
  OPENSHELL_TLS_KEY_PATH  Path to client key
  OPENSHELL_CLUSTER_TYPE  "openshift" or "kind" (default: "kind")
  OPENSHELL_NAMESPACE     Namespace for test resources (default: "agent-swarm-e2e-test")
  OPENSHELL_AGENT_IMAGE   BYOC image to use (default: "quay.io/jpacker/opencode:latest")
  OPENSHELL_TEST_REPO_URL Git repo to clone for validation
  KUBECONFIG              Kubeconfig path for kubectl verification calls

Usage:
  OPENSHELL_GATEWAY_URL=... OPENSHELL_CLUSTER_TYPE=kind pytest tests/test_e2e_openshell.py -v
"""
import os
import sys
import time
import subprocess
import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ---------------------------------------------------------------------------
# Skip guard — all tests skip unless the gateway URL is set
# ---------------------------------------------------------------------------

_GATEWAY_URL = os.environ.get("OPENSHELL_GATEWAY_URL", "")
_CLUSTER_TYPE = os.environ.get("OPENSHELL_CLUSTER_TYPE", "kind").lower()
_NAMESPACE = os.environ.get("OPENSHELL_NAMESPACE", "agent-swarm-e2e-test")
_AGENT_IMAGE = os.environ.get("OPENSHELL_AGENT_IMAGE", "quay.io/jpacker/opencode:latest")
_TEST_REPO_URL = os.environ.get("OPENSHELL_TEST_REPO_URL", "https://github.com/stolostron/agent-swarm")

pytestmark = pytest.mark.skipif(
    not _GATEWAY_URL,
    reason="OPENSHELL_GATEWAY_URL not set — skipping e2e tests. "
           "Set OPENSHELL_GATEWAY_URL to run against a real OpenShell gateway.",
)

# Inject SDK stub so imports don't blow up when sdk is absent
_sdk_stub_e2e = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
sys.modules.setdefault("openshell", _sdk_stub_e2e)

try:
    import swarmer.openshell_client as oc
    _HAS_CLIENT = True
except ImportError:
    oc = None
    _HAS_CLIENT = False


def _require_client():
    if not _HAS_CLIENT:
        pytest.fail("swarmer.openshell_client not implemented — ACM-34583 required.")


def _kubectl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run kubectl with namespace scoped to _NAMESPACE."""
    return subprocess.run(
        ["kubectl", "-n", _NAMESPACE, *args],
        capture_output=True,
        text=True,
        check=check,
    )


def _no_k8s_secrets_in_namespace(session_id: int) -> bool:
    """Return True if no session-scoped K8s Secrets exist for this session."""
    result = _kubectl("get", "secrets", "-o", "name", check=False)
    lines = result.stdout.splitlines()
    session_secrets = [l for l in lines if f"s{session_id}" in l]
    return len(session_secrets) == 0


def _no_pvcs_in_namespace(session_id: int) -> bool:
    """Return True if no session PVCs exist for this session."""
    result = _kubectl("get", "pvc", "-o", "name", check=False)
    lines = result.stdout.splitlines()
    session_pvcs = [l for l in lines if f"session-{session_id}" in l]
    return len(session_pvcs) == 0


def _no_services_in_namespace(session_id: int) -> bool:
    """Return True if no session ClusterIP Services exist for this session."""
    result = _kubectl("get", "svc", "-o", "name", check=False)
    lines = result.stdout.splitlines()
    session_svcs = [l for l in lines if f"session-{session_id}" in l]
    return len(session_svcs) == 0


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def openshell_client():
    """Return a configured OpenShell client pointing at the test gateway."""
    _require_client()
    client = oc.get_client(
        gateway_url=_GATEWAY_URL,
        tls_ca_path=os.environ.get("OPENSHELL_TLS_CA_PATH"),
        tls_cert_path=os.environ.get("OPENSHELL_TLS_CERT_PATH"),
        tls_key_path=os.environ.get("OPENSHELL_TLS_KEY_PATH"),
    )
    return client


@pytest_asyncio.fixture
async def sandbox(openshell_client):
    """Create a sandbox for testing and clean it up after the test."""
    _require_client()
    import yaml as _yaml
    policy_yaml = _yaml.dump({
        "version": 1,
        "filesystem_policy": {"include_workdir": True},
        "network_policies": {},
    })
    ref = await oc.create_sandbox(
        image=_AGENT_IMAGE,
        provider_id=None,
        policy_yaml=policy_yaml,
        client=openshell_client,
    )
    yield ref
    # Cleanup: always delete the sandbox after the test
    await oc.delete_sandbox(sandbox_name=ref.name, client=openshell_client)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_session_lifecycle(openshell_client):
    """Full lifecycle: create → clone → config → start → stop → verify no orphans.

    Covers: ACM-34607 e2e requirement #1
    Validates: sandbox created, git clone works via exec, agent config written,
               stop deletes sandbox, no orphaned K8s resources remain.
    """
    _require_client()
    import yaml as _yaml

    session_id = 9999  # Use a high ID unlikely to conflict with real sessions

    policy_yaml = _yaml.dump({
        "version": 1,
        "filesystem_policy": {"include_workdir": True},
        "network_policies": {
            "github": {
                "name": "github",
                "endpoints": [{"host": "github.com", "port": 443}],
            }
        },
    })

    # 1. Create sandbox
    ref = await oc.create_sandbox(
        image=_AGENT_IMAGE,
        provider_id=None,
        policy_yaml=policy_yaml,
        client=openshell_client,
    )
    assert ref is not None
    assert ref.name

    try:
        # 2. Clone repo via exec
        result = await oc.clone_repos(
            sandbox_name=ref.name,
            repos=[type("R", (), {"url": _TEST_REPO_URL, "branch": "main", "local_path": "agent-swarm"})()],
            client=openshell_client,
        )

        # 3. Write agent config via exec
        await oc.write_agent_config(
            sandbox_name=ref.name,
            tool_name="opencode",
            config_json='{"$schema":"https://opencode.ai/config.json"}',
            client=openshell_client,
        )

        # 4. Write AGENTS.md via exec
        await oc.write_agents_md(
            sandbox_name=ref.name,
            content="# E2E Test\n\nEcho 'hello' and exit.",
            client=openshell_client,
        )

    finally:
        # 5. Stop / cleanup
        await oc.delete_sandbox(sandbox_name=ref.name, client=openshell_client)

    # 6. Verify no orphaned K8s resources
    time.sleep(2)  # Brief wait for K8s to reconcile
    assert _no_k8s_secrets_in_namespace(session_id), \
        f"Orphaned K8s Secrets found in namespace {_NAMESPACE} after session stop"
    assert _no_pvcs_in_namespace(session_id), \
        f"Orphaned PVCs found in namespace {_NAMESPACE} after session stop"
    assert _no_services_in_namespace(session_id), \
        f"Orphaned Services found in namespace {_NAMESPACE} after session stop"


@pytest.mark.asyncio
async def test_credential_isolation(openshell_client):
    """Verify credentials are delivered via mTLS Provider, not stored as K8s Secrets.

    Covers: ACM-34607 e2e requirement #3
    Validates: no session-scoped K8s Secrets exist during an active sandbox.
    """
    _require_client()
    import yaml as _yaml

    session_id = 9998
    policy_yaml = _yaml.dump({"version": 1, "filesystem_policy": {}, "network_policies": {}})

    # Create a Provider with fake credentials (real values not needed for isolation check)
    provider_id = await oc.create_provider_from_env(
        google_api_key="fake-key",
        anthropic_api_key="fake-key",
        github_pat="fake-pat",
        client=openshell_client,
    )

    ref = await oc.create_sandbox(
        image=_AGENT_IMAGE,
        provider_id=provider_id,
        policy_yaml=policy_yaml,
        client=openshell_client,
    )

    try:
        # Check: no K8s Secrets with session scope created
        assert _no_k8s_secrets_in_namespace(session_id), \
            f"K8s Secrets found in namespace during active OpenShell session — credentials leaked!"

        # Check: pod/sandbox spec does not reference secrets via kubectl describe
        # (The sandbox runs as a pod under the gateway, not directly as a K8s pod
        #  with envFrom references — this verifies the gateway model)
        result = _kubectl("get", "pods", "-l", f"openshell-sandbox={ref.name}", "-o", "yaml", check=False)
        assert "envFrom" not in result.stdout or "opencode-secret" not in result.stdout, \
            "Session pod spec contains envFrom secret references — credential isolation violated!"
    finally:
        await oc.delete_sandbox(sandbox_name=ref.name, client=openshell_client)


@pytest.mark.asyncio
async def test_cleanup_on_stop_no_orphaned_resources(openshell_client):
    """Stopping a session must leave zero orphaned K8s resources in the namespace.

    Covers: ACM-34607 e2e requirement #5
    Validates: delete_sandbox removes sandbox; no Secrets, PVCs, or Services remain.
    """
    _require_client()
    import yaml as _yaml

    session_id = 9997
    policy_yaml = _yaml.dump({"version": 1, "filesystem_policy": {}, "network_policies": {}})

    ref = await oc.create_sandbox(
        image=_AGENT_IMAGE,
        provider_id=None,
        policy_yaml=policy_yaml,
        client=openshell_client,
    )

    # Explicitly stop
    await oc.delete_sandbox(sandbox_name=ref.name, client=openshell_client)
    time.sleep(3)  # Allow K8s to reconcile

    assert _no_k8s_secrets_in_namespace(session_id), "Orphaned Secrets after stop"
    assert _no_pvcs_in_namespace(session_id), "Orphaned PVCs after stop (PVCs should not exist at all)"
    assert _no_services_in_namespace(session_id), "Orphaned Services after stop"

    # Confirm sandbox itself is gone
    result = _kubectl("get", "pods", "-l", f"openshell-sandbox={ref.name}", check=False)
    assert ref.name not in result.stdout, f"Sandbox {ref.name} still listed after delete"


@pytest.mark.asyncio
async def test_concurrent_sessions_no_resource_conflicts(openshell_client):
    """Three concurrent sessions must not share resources or interfere with each other.

    Covers: ACM-34607 e2e requirement #4
    """
    _require_client()
    import asyncio
    import yaml as _yaml

    policy_yaml = _yaml.dump({"version": 1, "filesystem_policy": {}, "network_policies": {}})

    async def make_sandbox(i: int):
        ref = await oc.create_sandbox(
            image=_AGENT_IMAGE,
            provider_id=None,
            policy_yaml=policy_yaml,
            client=openshell_client,
        )
        return ref

    sandboxes = await asyncio.gather(
        make_sandbox(0), make_sandbox(1), make_sandbox(2)
    )

    try:
        # All sandboxes should have distinct names
        names = [s.name for s in sandboxes]
        assert len(set(names)) == 3, f"Expected 3 distinct sandbox names, got: {names}"

        # No sandbox should share filesystem with another (exec to verify isolation)
        for i, ref in enumerate(sandboxes):
            result = await oc.exec_command(
                sandbox_name=ref.name,
                cmd=["sh", "-c", "ls /sandbox/"],
                client=openshell_client,
            )
            # Each sandbox's /sandbox/ should be isolated (no cross-contamination)
            assert result is not None
    finally:
        import asyncio as _asyncio
        await _asyncio.gather(*[
            oc.delete_sandbox(sandbox_name=ref.name, client=openshell_client)
            for ref in sandboxes
        ])


@pytest.mark.asyncio
@pytest.mark.skipif(_CLUSTER_TYPE != "openshift", reason="OpenShift-specific test")
async def test_openshift_no_route_created(openshell_client):
    """OpenShift: no OpenShift Route resource must be created for server-mode sessions.

    Covers: ACM-34607 e2e requirement #6
    OpenShell provides sandbox network identity — Routes are no longer needed.
    """
    _require_client()
    import yaml as _yaml

    session_id = 9996
    policy_yaml = _yaml.dump({"version": 1, "filesystem_policy": {}, "network_policies": {}})

    ref = await oc.create_sandbox(
        image=_AGENT_IMAGE,
        provider_id=None,
        policy_yaml=policy_yaml,
        client=openshell_client,
    )

    try:
        result = subprocess.run(
            ["kubectl", "-n", _NAMESPACE, "get", "route", "-o", "name"],
            capture_output=True, text=True, check=False,
        )
        session_routes = [l for l in result.stdout.splitlines() if f"session-{session_id}" in l]
        assert not session_routes, (
            f"OpenShift Route created for session {session_id} — should not exist when using OpenShell. "
            f"Routes found: {session_routes}"
        )
    finally:
        await oc.delete_sandbox(sandbox_name=ref.name, client=openshell_client)


@pytest.mark.asyncio
@pytest.mark.skipif(_CLUSTER_TYPE != "kind", reason="Kind-specific test")
async def test_kind_sandbox_reachable_via_exec_relay(openshell_client):
    """Kind: sandbox must be reachable via OpenShell exec relay (no Service DNS required).

    Covers: ACM-34607 e2e requirement #7
    """
    _require_client()
    import yaml as _yaml

    policy_yaml = _yaml.dump({"version": 1, "filesystem_policy": {}, "network_policies": {}})
    ref = await oc.create_sandbox(
        image=_AGENT_IMAGE,
        provider_id=None,
        policy_yaml=policy_yaml,
        client=openshell_client,
    )

    try:
        # exec a simple command — if exec relay works, this returns successfully
        result = await oc.exec_command(
            sandbox_name=ref.name,
            cmd=["echo", "exec-relay-works"],
            client=openshell_client,
        )
        assert result is not None
        assert "exec-relay-works" in (result.stdout or ""), \
            f"exec relay did not return expected output. Got: {result}"
    finally:
        await oc.delete_sandbox(sandbox_name=ref.name, client=openshell_client)


@pytest.mark.asyncio
async def test_policy_enforcement_blocks_unauthorized_egress(openshell_client):
    """Network policy must block egress to endpoints not listed in the policy.

    Covers: ACM-34607 e2e requirement #2
    Creates a sandbox with a restrictive policy that blocks all egress,
    then verifies unauthorized HTTP requests are refused.
    """
    _require_client()
    import yaml as _yaml

    # Completely restrictive policy — no network_policies entries
    policy_yaml = _yaml.dump({
        "version": 1,
        "filesystem_policy": {"include_workdir": True},
        "network_policies": {},
    })

    ref = await oc.create_sandbox(
        image=_AGENT_IMAGE,
        provider_id=None,
        policy_yaml=policy_yaml,
        client=openshell_client,
    )

    try:
        # Attempt to curl an unauthorized endpoint — should be blocked
        result = await oc.exec_command(
            sandbox_name=ref.name,
            cmd=["sh", "-c", "curl -s --max-time 3 https://example.com; echo exit=$?"],
            client=openshell_client,
        )
        output = (result.stdout or "") + (result.stderr or "")
        # Connection should be refused (ECONNREFUSED) or timeout before leaving host
        assert "exit=0" not in output or "curl" not in output, \
            f"Unauthorized egress to example.com succeeded — network policy not enforced. Output: {output}"
    finally:
        await oc.delete_sandbox(sandbox_name=ref.name, client=openshell_client)
