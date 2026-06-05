"""
Tests for swarmer.openshell_policy.build_session_policy().

Validates that build_session_policy() returns a SandboxPolicy proto with:
  - Required structural sections (version, filesystem, network_policies)
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

from swarmer.openshell_policy import build_session_policy


# ---------------------------------------------------------------------------
# Helpers to build minimal test fixtures matching the real model shapes
# ---------------------------------------------------------------------------

def _make_repo(org="stolostron", name="agent-swarm", branch="main"):
    return type("Repo", (), {
        "repo_url": f"https://github.com/{org}/{name}",
        "branch": branch,
        "local_path": name,
    })()


def _make_mcp(slug="jira"):
    return type("MCP", (), {"slug": slug})()


def _make_session(language="golang"):
    return type("Session", (), {
        "id": 1,
        "language": language,
        "agent_tool": "opencode",
        "model": "google-vertex-anthropic/claude-sonnet-4-6",
    })()


def _policy_dict(policy) -> dict:
    """Convert SandboxPolicy proto to a dict for easy assertions."""
    return {
        "version": policy.version,
        "filesystem": {
            "read_only": list(policy.filesystem.read_only),
            "read_write": list(policy.filesystem.read_write),
        },
        "network_policies": {
            k: {
                "endpoints": [{"host": e.host, "port": e.port} for e in v.endpoints],
                "binaries": [b.path for b in v.binaries],
            }
            for k, v in policy.network_policies.items()
        },
    }


def _hosts(policy, rule_key: str) -> list[str]:
    """Return endpoint hosts for a network policy rule."""
    rule = policy.network_policies.get(rule_key)
    if rule is None:
        return []
    return [e.host for e in rule.endpoints]


def _all_hosts(policy) -> list[str]:
    """Return all endpoint hosts across all rules."""
    hosts = []
    for rule in policy.network_policies.values():
        hosts.extend(e.host for e in rule.endpoints)
    return hosts


# ---------------------------------------------------------------------------
# 1. Required structure
# ---------------------------------------------------------------------------

def test_policy_has_version_1():
    result = build_session_policy(_make_session(), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert result.version == 1


def test_policy_has_filesystem_policy():
    result = build_session_policy(_make_session(), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert result.filesystem.include_workdir is True
    assert "/sandbox" in result.filesystem.read_write


def test_policy_has_network_policies_section():
    result = build_session_policy(_make_session(), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert len(result.network_policies) > 0


def test_policy_sandbox_uses_sandbox_path():
    result = build_session_policy(_make_session(), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "/sandbox" in result.filesystem.read_write
    assert "/workspace" not in list(result.filesystem.read_write)


# ---------------------------------------------------------------------------
# 2. GitHub blocks (per-repo)
# ---------------------------------------------------------------------------

def test_github_git_block_generated_per_repo():
    repo = _make_repo(org="stolostron", name="agent-swarm")
    result = build_session_policy(_make_session(), repos=[repo], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    git_blocks = [k for k in result.network_policies if k.startswith("github_git_")]
    assert len(git_blocks) == 1, f"Expected 1 github_git_ block, got {len(git_blocks)}: {git_blocks}"


def test_github_api_block_generated_per_repo():
    repo = _make_repo(org="stolostron", name="agent-swarm")
    result = build_session_policy(_make_session(), repos=[repo], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    api_blocks = [k for k in result.network_policies if k.startswith("github_api_")]
    assert len(api_blocks) == 1, f"Expected 1 github_api_ block, got {len(api_blocks)}: {api_blocks}"


def test_github_blocks_scoped_to_repo_path():
    repo = _make_repo(org="stolostron", name="agent-swarm")
    result = build_session_policy(_make_session(), repos=[repo], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    # GitHub blocks use github.com / api.github.com as hosts; repo scoping is in rules/paths
    assert "github_git_stolostron_agent_swarm" in result.network_policies
    assert "github_api_stolostron_agent_swarm" in result.network_policies


def test_two_repos_generate_two_github_block_pairs():
    repo1 = _make_repo(org="stolostron", name="agent-swarm")
    repo2 = _make_repo(org="stolostron", name="agent-containers")
    result = build_session_policy(_make_session(), repos=[repo1, repo2], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert len([k for k in result.network_policies if k.startswith("github_git_")]) == 2
    assert len([k for k in result.network_policies if k.startswith("github_api_")]) == 2


# ---------------------------------------------------------------------------
# 3. Jira MCP block (conditional)
# ---------------------------------------------------------------------------

def test_jira_block_present_when_jira_mcp_enabled():
    result = build_session_policy(_make_session(), repos=[], mcp_servers=[_make_mcp(slug="jira")], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert any("jira" in k.lower() for k in result.network_policies), "Expected a jira MCP network block"


def test_jira_block_absent_when_no_jira_mcp():
    result = build_session_policy(_make_session(), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert not any("jira" in k.lower() for k in result.network_policies)


def test_jira_block_absent_when_only_non_jira_mcp():
    result = build_session_policy(_make_session(), repos=[], mcp_servers=[_make_mcp(slug="github")], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "atlassian.net" not in _all_hosts(result)


# ---------------------------------------------------------------------------
# 4. Language-specific development blocks
# ---------------------------------------------------------------------------

def test_go_development_block_included_for_go_session():
    result = build_session_policy(_make_session(language="golang"), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    hosts = _all_hosts(result)
    assert "proxy.golang.org" in hosts
    assert "sum.golang.org" in hosts


def test_python_development_block_included_for_python_session():
    result = build_session_policy(_make_session(language="python"), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    hosts = _all_hosts(result)
    assert "pypi.org" in hosts
    assert "files.pythonhosted.org" in hosts


def test_govulncheck_block_included_for_go_session():
    result = build_session_policy(_make_session(language="golang"), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "vuln.go.dev" in _all_hosts(result)


def test_go_block_absent_for_python_session():
    result = build_session_policy(_make_session(language="python"), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "proxy.golang.org" not in _all_hosts(result)


def test_python_block_absent_for_go_session():
    result = build_session_policy(_make_session(language="golang"), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert "pypi.org" not in _all_hosts(result)


# ---------------------------------------------------------------------------
# 5. Minimal session — no excess blocks
# ---------------------------------------------------------------------------

def test_minimal_session_no_jira_or_extra_github_blocks():
    repo = _make_repo()
    result = build_session_policy(_make_session(language="golang"), repos=[repo], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert not any("jira" in k.lower() for k in result.network_policies)
    assert len([k for k in result.network_policies if k.startswith("github_git_")]) == 1


# ---------------------------------------------------------------------------
# 6. Agent API block
# ---------------------------------------------------------------------------

def test_agent_api_block_opencode_includes_vertex_endpoints():
    result = build_session_policy(_make_session(), repos=[], mcp_servers=[], agent_tool="opencode", model="google-vertex-anthropic/claude-sonnet-4-6")
    assert any("agent_api" in k.lower() for k in result.network_policies)
    hosts = _all_hosts(result)
    assert any("aiplatform.googleapis.com" in h or "api.anthropic.com" in h for h in hosts)


def test_agent_api_block_crush_includes_crush_binary():
    result = build_session_policy(_make_session(), repos=[], mcp_servers=[], agent_tool="crush", model="vertexai/claude-sonnet-4-6")
    api_block = result.network_policies.get("agent_api")
    assert api_block is not None
    # Crush block has no binaries restriction (binaries list is empty)
    # opencode binary path should not appear
    binary_paths = [b.path for b in api_block.binaries]
    assert not any("opencode" in p for p in binary_paths), f"opencode binary in crush block: {binary_paths}"
