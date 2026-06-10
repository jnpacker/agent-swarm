"""
Tests for swarmer.openshell_client — the OpenShell SDK wrapper.

Validates the session lifecycle helpers:
  - create_provider() builds env-var dicts from DB credentials (no K8s Secrets)
  - create_sandbox() calls SandboxClient.create() and wait_ready()
  - exec helpers (clone_repos, write_agent_config, write_agents_md, start_agent)
    use /sandbox/ paths, not /workspace/
  - delete_sandbox() calls SandboxClient.delete() without touching PVCs
"""
import os
import sys

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ---------------------------------------------------------------------------
# Inject openshell SDK stub so swarmer.openshell_client imports succeed
# without a real installed package.
# ---------------------------------------------------------------------------


class _SandboxTemplate:
    def __init__(self):
        self.image = ""
        self.environment = {}


class _SandboxSpec:
    def __init__(self):
        self.template = _SandboxTemplate()
        self.environment = {}
        self.policy = None


_proto_stub = MagicMock()
_proto_stub.openshell_pb2 = MagicMock()
_proto_stub.openshell_pb2.SandboxSpec = _SandboxSpec

_sdk_stub = MagicMock()
_sdk_stub.SandboxClient = MagicMock
_sdk_stub.TlsConfig = MagicMock
_sdk_stub._proto = _proto_stub

# Save any real openshell modules already in sys.modules so we can restore
# them after importing swarmer.openshell_client with our stubs.  This prevents
# the stubs from polluting sys.modules for other test files (e.g.
# test_openshell_policy.py) that need the real protobuf classes.
_saved_modules = {k: v for k, v in sys.modules.items() if "openshell" in k}

sys.modules["openshell"] = _sdk_stub
sys.modules["openshell._proto"] = _proto_stub
sys.modules["openshell._proto.openshell_pb2"] = _proto_stub.openshell_pb2

import swarmer.openshell_client as oc  # noqa: E402

# Restore real openshell modules (or remove the stubs if none were there before)
for _k in ("openshell", "openshell._proto", "openshell._proto.openshell_pb2"):
    if _k in _saved_modules:
        sys.modules[_k] = _saved_modules[_k]
    else:
        sys.modules.pop(_k, None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sdk_client():
    """Mock object mimicking the synchronous openshell.SandboxClient interface."""
    client = MagicMock()
    ref = MagicMock()
    ref.name = "sandbox-s42-abc1"
    ref.id = "sandbox-s42-abc1"
    client.create = MagicMock(return_value=ref)
    client.get = MagicMock(return_value=ref)
    client.wait_ready = MagicMock(return_value=ref)
    client.exec = MagicMock(return_value=MagicMock(exit_code=0, stdout=""))
    client.delete = MagicMock(return_value=True)
    return client


@pytest.fixture
def session():
    s = MagicMock()
    s.id = 42
    s.mode = "tui"
    s.agent_tool = "opencode"
    s.model = "google-vertex-anthropic/claude-sonnet-4-6"
    s.instruction_prompt = ""
    s.sandbox_name = None
    repo = MagicMock()
    repo.url = "https://github.com/stolostron/agent-swarm"
    repo.branch = "main"
    repo.local_path = "agent-swarm"
    s.repos = [repo]
    return s


@pytest.fixture
def workspace_secret():
    secret = MagicMock()
    secret.google_api_key = "gkey-test"
    secret.anthropic_api_key = "akey-test"
    secret.google_cloud_project = "my-project"
    return secret


@pytest.fixture
def github_pat():
    pat = MagicMock()
    pat.token = "ghp_testtoken"
    pat.username = "jpacker"
    return pat


# ---------------------------------------------------------------------------
# 1. Provider creation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_provider_returns_empty_for_no_mcp(sdk_client, session, workspace_secret):
    """AI credentials no longer go via env vars — create_provider returns only MCP vars."""
    env_vars = await oc.create_provider(
        session=session,
        workspace_secret=workspace_secret,
        github_pat=None,
        mcp_servers=[],
    )
    assert isinstance(env_vars, dict)
    assert "GOOGLE_API_KEY" not in env_vars
    assert "ANTHROPIC_API_KEY" not in env_vars
    assert env_vars == {}


@pytest.mark.asyncio
async def test_create_provider_does_not_create_k8s_agent_secret(session, workspace_secret):
    # k8s.create_session_agent_secret has been removed from k8s.py as part of the
    # OpenShell migration dead-code cleanup.  create_provider() cannot call it.
    await oc.create_provider(
        session=session,
        workspace_secret=workspace_secret,
        github_pat=None,
        mcp_servers=[],
    )


@pytest.mark.asyncio
async def test_create_provider_does_not_create_k8s_pat_secret(session, workspace_secret, github_pat):
    # k8s.create_session_pat_secret has been removed from k8s.py as part of the
    # OpenShell migration dead-code cleanup.  create_provider() cannot call it.
    await oc.create_provider(
        session=session,
        workspace_secret=workspace_secret,
        github_pat=github_pat,
        mcp_servers=[],
    )


@pytest.mark.asyncio
async def test_create_provider_no_github_pat_in_env(session, workspace_secret, github_pat):
    """GitHub PAT is now injected via the github gateway provider, not env vars."""
    env_vars = await oc.create_provider(
        session=session,
        workspace_secret=workspace_secret,
        github_pat=github_pat,
        mcp_servers=[],
    )
    assert "GITHUB_PAT" not in env_vars
    assert "GH_TOKEN" not in env_vars


@pytest.mark.asyncio
async def test_create_provider_jira_not_in_env_vars(session, workspace_secret):
    """Jira credentials must NOT appear in env_vars from create_provider().

    Jira credentials go through the OpenShell Provider API, not raw env vars.
    create_provider() only returns workspace extra env vars supplied via extra_env.
    """
    jira_mcp = MagicMock()
    jira_mcp.slug = "atlassian-jira"
    jira_mcp.jira_server_url = "https://redhat.atlassian.net"
    jira_mcp.jira_access_token = "tok-test"
    jira_mcp.jira_email = "test@redhat.com"
    env_vars = await oc.create_provider(
        session=session,
        workspace_secret=workspace_secret,
        github_pat=None,
        mcp_servers=[jira_mcp],
    )
    assert "JIRA_SERVER_URL" not in env_vars, (
        "Jira credentials must go through Provider API, not raw env_vars"
    )
    assert "JIRA_ACCESS_TOKEN" not in env_vars
    assert "JIRA_EMAIL" not in env_vars


@pytest.mark.asyncio
async def test_create_provider_includes_workspace_extra_env_vars(session, workspace_secret):
    """create_provider() returns workspace extra env vars passed via extra_env (from DB)."""
    env_vars = await oc.create_provider(
        session=session,
        workspace_secret=workspace_secret,
        github_pat=None,
        mcp_servers=[],
        extra_env={"MY_VAR": "hello", "FOO": "bar"},
    )
    assert env_vars.get("MY_VAR") == "hello"
    assert env_vars.get("FOO") == "bar"


@pytest.mark.asyncio
async def test_create_provider_empty_when_no_extra_env(session, workspace_secret):
    """create_provider() returns {} when no extra_env is supplied."""
    env_vars = await oc.create_provider(
        session=session,
        workspace_secret=workspace_secret,
        github_pat=None,
        mcp_servers=[],
    )
    assert env_vars == {}


# ---------------------------------------------------------------------------
# 2. Sandbox creation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_sandbox_passes_byoc_image(sdk_client):
    image = "quay.io/jpacker/opencode:latest"
    with patch.object(oc, "_get_client", return_value=sdk_client), \
         patch.object(oc, "_wait_sandbox_ready", new=AsyncMock()):
        await oc.create_sandbox(image=image, env_vars={}, policy=None)
    sdk_client.create.assert_called_once()
    spec = sdk_client.create.call_args.kwargs["spec"]
    assert spec.template.image == image


@pytest.mark.asyncio
async def test_wait_ready_called_after_create(sdk_client):
    """_wait_sandbox_ready (conditions-based) is called instead of sdk client.wait_ready."""
    with patch.object(oc, "_get_client", return_value=sdk_client), \
         patch.object(oc, "_wait_sandbox_ready", new=AsyncMock()) as mock_ready:
        await oc.create_sandbox(
            image="quay.io/jpacker/opencode:latest", env_vars={}, policy=None
        )
    mock_ready.assert_called_once()


@pytest.mark.asyncio
async def test_create_sandbox_does_not_create_pvc(sdk_client):
    # k8s_session.ensure_session_pvc has been removed — k8s_session no longer exists.
    # Verify create_sandbox succeeds without any PVC creation.
    with patch.object(oc, "_get_client", return_value=sdk_client), \
         patch.object(oc, "_wait_sandbox_ready", new=AsyncMock()):
        await oc.create_sandbox(
            image="quay.io/jpacker/opencode:latest", env_vars={}, policy=None
        )


# ---------------------------------------------------------------------------
# 3. Exec operations: config, AGENTS.md, agent startup
# (git clone now uses exec_command inline in _setup_openshell_sandbox)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_config_write_exec_uses_sandbox_config_path(sdk_client):
    sandbox_name = "sandbox-s42-abc1"
    config_json = '{"$schema": "https://opencode.ai/config.json", "mcpServers": {}}'
    with patch.object(oc, "_get_client", return_value=sdk_client):
        await oc.write_agent_config(
            sandbox_name=sandbox_name,
            tool_name="opencode",
            config_json=config_json,
        )
    sdk_client.exec.assert_called_once()
    calls_repr = str(sdk_client.exec.call_args)
    assert "/sandbox/" in calls_repr
    assert "/workspace/" not in calls_repr


@pytest.mark.asyncio
async def test_agents_md_exec_writes_to_sandbox(sdk_client):
    sandbox_name = "sandbox-s42-abc1"
    with patch.object(oc, "_get_client", return_value=sdk_client):
        await oc.write_agents_md(sandbox_name=sandbox_name, content="# Instructions\n\nFix the bug.")
    sdk_client.exec.assert_called_once()
    calls_repr = str(sdk_client.exec.call_args)
    assert "AGENTS.md" in calls_repr


@pytest.mark.asyncio
async def test_start_agent_exec_called_with_agent_cmd(sdk_client):
    sandbox_name = "sandbox-s42-abc1"
    cmd = ["opencode", "serve", "--hostname", "0.0.0.0", "--port", "4096"]
    with patch.object(oc, "_get_client", return_value=sdk_client):
        await oc.start_agent(sandbox_name=sandbox_name, cmd=cmd)
    sdk_client.exec.assert_called_once()
    calls_repr = str(sdk_client.exec.call_args)
    assert "opencode" in calls_repr


# ---------------------------------------------------------------------------
# 4. Session stop / cleanup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stop_calls_delete_sandbox(sdk_client):
    sandbox_name = "sandbox-s42-abc1"
    with patch.object(oc, "_get_client", return_value=sdk_client):
        await oc.delete_sandbox(sandbox_name=sandbox_name)
    sdk_client.delete.assert_called_once_with(sandbox_name)


# ---------------------------------------------------------------------------
# get_draft_chunks tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_draft_chunks_returns_serializable_list(sdk_client):
    """get_draft_chunks() calls GetDraftPolicy and returns a list of dicts."""
    # Build a fake chunk proto-like object
    fake_ep = MagicMock()
    fake_ep.host = "vuln.go.dev"
    fake_ep.port = 443
    fake_ep.protocol = "rest"

    fake_bin = MagicMock()
    fake_bin.path = "/usr/local/go/bin/govulncheck"
    fake_bin.harness = True

    fake_chunk = MagicMock()
    fake_chunk.id = "chunk-abc"
    fake_chunk.status = "pending"
    fake_chunk.rule_name = "govulncheck"
    fake_chunk.proposed_rule.endpoints = [fake_ep]
    fake_chunk.proposed_rule.binaries = [fake_bin]

    fake_dp = MagicMock()
    fake_dp.chunks = [fake_chunk]
    sdk_client._stub.GetDraftPolicy.return_value = fake_dp

    with patch.object(oc, "_get_client", return_value=sdk_client):
        result = await oc.get_draft_chunks("sandbox-test")

    assert len(result) == 1
    c = result[0]
    assert c["id"] == "chunk-abc"
    assert c["status"] == "pending"
    assert c["rule_name"] == "govulncheck"
    assert c["endpoints"][0]["host"] == "vuln.go.dev"
    assert c["endpoints"][0]["port"] == 443
    assert c["binaries"][0]["path"] == "/usr/local/go/bin/govulncheck"
    assert c["binaries"][0]["harness"] is True


@pytest.mark.asyncio
async def test_get_draft_chunks_returns_empty_on_error(sdk_client):
    """get_draft_chunks() returns [] when the gateway call fails."""
    sdk_client._stub.GetDraftPolicy.side_effect = Exception("gateway unavailable")
    with patch.object(oc, "_get_client", return_value=sdk_client):
        result = await oc.get_draft_chunks("sandbox-gone")
    assert result == []


@pytest.mark.asyncio
async def test_stop_does_not_call_pvc_delete(sdk_client):
    # k8s_session.delete_session_pvc has been removed — k8s_session no longer exists.
    # Verify delete_sandbox succeeds without any PVC deletion.
    with patch.object(oc, "_get_client", return_value=sdk_client):
        await oc.delete_sandbox(sandbox_name="sandbox-s42-abc1")


@pytest.mark.asyncio
async def test_stop_does_not_call_cleanup_session_secrets(sdk_client):
    # k8s.cleanup_session_secrets has been removed from k8s.py as part of the
    # OpenShell migration dead-code cleanup.  delete_sandbox() cannot call it.
    with patch.object(oc, "_get_client", return_value=sdk_client):
        await oc.delete_sandbox(sandbox_name="sandbox-s42-abc1")
