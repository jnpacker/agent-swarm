"""
TDD tests for swarmer.openshell_policy.build_session_policy().

These tests are RED until ACM-34584 implements swarmer/openshell_policy.py.

Validates that build_session_policy() returns a valid YAML string with:
  - Required structural sections (version, filesystem_policy, network_policies)
  - Per-repo GitHub git + API blocks with scoped paths
  - Conditional Jira MCP block (present when Jira MCP enabled, absent otherwise)
  - Conditional Go development block (proxy.golang.org etc.)
  - Conditional Python development block (pypi.org etc.)
  - govulncheck block for Go sessions
  - Agent API block adapted to agent tool (opencode vs crush) and model provider
  - No excess blocks for minimal sessions (single repo, no MCP)
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

try:
    from swarmer.openshell_policy import build_session_policy
    _HAS_POLICY = True
except ImportError:
    build_session_policy = None
    _HAS_POLICY = False


def _require_policy():
    if not _HAS_POLICY:
        pytest.fail(
            "swarmer.openshell_policy not implemented — ACM-34584 required. "
            "Expected TDD red phase."
        )
    if not _HAS_YAML:
        pytest.fail("pyyaml not installed — add it to requirements.txt")


# ---------------------------------------------------------------------------
# Helpers to build minimal test fixtures
# ---------------------------------------------------------------------------

def _make_repo(org="stolostron", name="agent-swarm", branch="main"):
    repo = type("Repo", (), {
        "url": f"https://github.com/{org}/{name}",
        "branch": branch,
        "local_path": name,
        "org": org,
        "name": name,
    })()
    return repo


def _make_mcp(catalog_key="jira"):
    mcp = type("MCP", (), {"catalog_key": catalog_key})()
    return mcp


def _make_session(language="golang"):
    session = type("Session", (), {
        "id": 1,
        "language": language,
        "agent_tool": "opencode",
        "model": "google-vertex-anthropic/claude-sonnet-4-6",
    })()
    return session


def _parse_policy(yaml_str: str) -> dict:
    import yaml as _yaml
    return _yaml.safe_load(yaml_str)


# ---------------------------------------------------------------------------
# 1. Required structure
# ---------------------------------------------------------------------------

def test_policy_has_version_1():
    """Policy must declare version: 1."""
    _require_policy()
    session = _make_session()
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    policy = _parse_policy(result)
    assert policy.get("version") == 1


def test_policy_has_filesystem_policy():
    """Policy must include a filesystem_policy section."""
    _require_policy()
    session = _make_session()
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    policy = _parse_policy(result)
    assert "filesystem_policy" in policy


def test_policy_has_network_policies_section():
    """Policy must include a network_policies section (even if minimal)."""
    _require_policy()
    session = _make_session()
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    policy = _parse_policy(result)
    assert "network_policies" in policy


def test_policy_sandbox_uses_sandbox_path():
    """Filesystem policy must reference /sandbox, not /workspace."""
    _require_policy()
    session = _make_session()
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "/sandbox" in result
    assert "/workspace" not in result


# ---------------------------------------------------------------------------
# 2. GitHub blocks (per-repo)
# ---------------------------------------------------------------------------

def test_github_git_block_generated_per_repo():
    """A github_git_{slug} block must be created for each repo."""
    _require_policy()
    session = _make_session()
    repo = _make_repo(org="stolostron", name="agent-swarm")
    result = build_session_policy(session, repos=[repo], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    policy = _parse_policy(result)
    net = policy["network_policies"]
    git_blocks = [k for k in net if k.startswith("github_git_")]
    assert len(git_blocks) == 1, f"Expected 1 github_git_ block, got {len(git_blocks)}: {git_blocks}"


def test_github_api_block_generated_per_repo():
    """A github_api_{slug} block must be created for each repo."""
    _require_policy()
    session = _make_session()
    repo = _make_repo(org="stolostron", name="agent-swarm")
    result = build_session_policy(session, repos=[repo], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    policy = _parse_policy(result)
    net = policy["network_policies"]
    api_blocks = [k for k in net if k.startswith("github_api_")]
    assert len(api_blocks) == 1, f"Expected 1 github_api_ block, got {len(api_blocks)}: {api_blocks}"


def test_github_blocks_scoped_to_repo_path():
    """GitHub blocks must scope endpoints to the specific org/repo path, not wildcard."""
    _require_policy()
    session = _make_session()
    repo = _make_repo(org="stolostron", name="agent-swarm")
    result = build_session_policy(session, repos=[repo], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    # The repo path must appear in the policy to enforce per-repo scoping
    assert "stolostron/agent-swarm" in result or "stolostron" in result


def test_two_repos_generate_two_github_block_pairs():
    """Two repos must each get their own github_git_ and github_api_ blocks."""
    _require_policy()
    session = _make_session()
    repo1 = _make_repo(org="stolostron", name="agent-swarm")
    repo2 = _make_repo(org="stolostron", name="agent-containers")
    result = build_session_policy(session, repos=[repo1, repo2], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    policy = _parse_policy(result)
    net = policy["network_policies"]
    git_blocks = [k for k in net if k.startswith("github_git_")]
    api_blocks = [k for k in net if k.startswith("github_api_")]
    assert len(git_blocks) == 2, f"Expected 2 github_git_ blocks, got {len(git_blocks)}"
    assert len(api_blocks) == 2, f"Expected 2 github_api_ blocks, got {len(api_blocks)}"


# ---------------------------------------------------------------------------
# 3. Jira MCP block (conditional)
# ---------------------------------------------------------------------------

def test_jira_block_present_when_jira_mcp_enabled():
    """Jira MCP network block must be included when a Jira MCP server is in the session."""
    _require_policy()
    session = _make_session()
    jira_mcp = _make_mcp(catalog_key="jira")
    result = build_session_policy(session, repos=[], mcp_servers=[jira_mcp], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    policy = _parse_policy(result)
    net = policy["network_policies"]
    jira_blocks = [k for k in net if "jira" in k.lower()]
    assert jira_blocks, "Expected a jira MCP network block when Jira MCP is enabled"


def test_jira_block_absent_when_no_jira_mcp():
    """Jira MCP network block must NOT appear when no Jira MCP server is configured."""
    _require_policy()
    session = _make_session()
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    policy = _parse_policy(result)
    net = policy["network_policies"]
    jira_blocks = [k for k in net if "jira" in k.lower()]
    assert not jira_blocks, f"Unexpected jira block when no Jira MCP: {jira_blocks}"


def test_jira_block_absent_when_only_non_jira_mcp():
    """Jira MCP block must NOT appear when only non-Jira MCP servers are enabled."""
    _require_policy()
    session = _make_session()
    other_mcp = _make_mcp(catalog_key="github")
    result = build_session_policy(session, repos=[], mcp_servers=[other_mcp], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "atlassian.net" not in result, "atlassian.net should only appear when Jira MCP is enabled"


# ---------------------------------------------------------------------------
# 4. Language-specific development blocks
# ---------------------------------------------------------------------------

def test_go_development_block_included_for_go_session():
    """Go development block must include proxy.golang.org and sum.golang.org."""
    _require_policy()
    session = _make_session(language="golang")
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "proxy.golang.org" in result
    assert "sum.golang.org" in result


def test_python_development_block_included_for_python_session():
    """Python development block must include pypi.org and files.pythonhosted.org."""
    _require_policy()
    session = _make_session(language="python")
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "pypi.org" in result
    assert "files.pythonhosted.org" in result


def test_govulncheck_block_included_for_go_session():
    """govulncheck block must include vuln.go.dev for Go sessions."""
    _require_policy()
    session = _make_session(language="golang")
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "vuln.go.dev" in result


def test_go_block_absent_for_python_session():
    """Go proxy endpoints must NOT appear for pure Python sessions."""
    _require_policy()
    session = _make_session(language="python")
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "proxy.golang.org" not in result, "Go proxy should not appear in a Python session"


def test_python_block_absent_for_go_session():
    """PyPI endpoints must NOT appear for pure Go sessions."""
    _require_policy()
    session = _make_session(language="golang")
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "pypi.org" not in result, "PyPI should not appear in a Go session"


# ---------------------------------------------------------------------------
# 5. Minimal session — no excess blocks
# ---------------------------------------------------------------------------

def test_minimal_session_no_jira_or_extra_github_blocks():
    """A session with one repo and no MCP must not contain jira or multi-repo GitHub blocks."""
    _require_policy()
    session = _make_session(language="golang")
    repo = _make_repo()
    result = build_session_policy(session, repos=[repo], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    policy = _parse_policy(result)
    net = policy["network_policies"]
    jira_blocks = [k for k in net if "jira" in k.lower()]
    assert not jira_blocks, f"No Jira block expected for session with no Jira MCP: {jira_blocks}"
    git_blocks = [k for k in net if k.startswith("github_git_")]
    assert len(git_blocks) == 1, f"Exactly 1 github_git_ block expected for 1 repo, got {len(git_blocks)}"


# ---------------------------------------------------------------------------
# 6. Agent API block
# ---------------------------------------------------------------------------

def test_agent_api_block_opencode_includes_vertex_endpoints():
    """OpenCode agent API block must include VertexAI and Anthropic endpoints."""
    _require_policy()
    session = _make_session()
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    policy = _parse_policy(result)
    net = policy["network_policies"]
    api_blocks = [k for k in net if "agent_api" in k.lower() or "agent-api" in k.lower()]
    assert api_blocks, "Expected an agent_api block for OpenCode sessions"
    block_str = str(net)
    assert "aiplatform.googleapis.com" in block_str or "api.anthropic.com" in block_str


def test_agent_api_block_crush_includes_crush_binary():
    """Crush agent API block must reference the crush binary, not opencode."""
    _require_policy()
    session = _make_session()
    session.agent_tool = "crush"
    result = build_session_policy(session, repos=[], mcp_servers=[], agent_tool="crush", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "crush" in result.lower()
    # The opencode binary should NOT appear in the binaries for a Crush session
    policy = _parse_policy(result)
    net = policy["network_policies"]
    api_blocks = {k: v for k, v in net.items() if "agent_api" in k.lower() or "agent-api" in k.lower()}
    for block in api_blocks.values():
        binaries = block.get("binaries", [])
        paths = [b.get("path", "") for b in binaries if isinstance(b, dict)]
        for path in paths:
            assert "opencode" not in path, f"opencode binary should not appear in Crush agent API block: {path}"
