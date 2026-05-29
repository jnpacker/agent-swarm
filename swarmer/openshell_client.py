"""
OpenShell sandbox client wrapper for AgentSwarm session lifecycle.

Wraps the OpenShell Python SDK (pip install openshell) to provide async
functions for sandbox create/delete, credential Provider creation (replaces
K8s Secrets), and exec operations for git clone, config injection, and agent
startup. All exec paths target /sandbox/ — never /workspace/.
"""
import logging
from typing import Any

log = logging.getLogger(__name__)


def _get_client():
    """Return a configured SandboxClient from settings."""
    from swarmer.config import settings
    from openshell import SandboxClient, TlsConfig
    tls = None
    if settings.openshell_tls_ca_path:
        tls = TlsConfig(
            ca_path=settings.openshell_tls_ca_path,
            cert_path=settings.openshell_tls_cert_path,
            key_path=settings.openshell_tls_key_path,
        )
    return SandboxClient(settings.openshell_gateway_url, tls=tls)


def get_client(
    gateway_url: str,
    tls_ca_path: str | None = None,
    tls_cert_path: str | None = None,
    tls_key_path: str | None = None,
):
    """Public factory for e2e tests and direct usage."""
    from openshell import SandboxClient, TlsConfig
    tls = None
    if tls_ca_path:
        tls = TlsConfig(ca_path=tls_ca_path, cert_path=tls_cert_path, key_path=tls_key_path)
    return SandboxClient(gateway_url, tls=tls)


async def create_provider(
    session,
    workspace_secret,
    github_pat,
    mcp_servers: list,
    client=None,
):
    """Create an OpenShell Provider from DB credentials (replaces K8s Secrets).

    Credential injection path: AgentSwarm DB -> OpenShell Provider via mTLS.
    K8s Secret functions (create_session_agent_secret, create_session_pat_secret,
    create_session_mcp_secret) are never called from this path.
    """
    if client is None:
        client = _get_client()

    env_vars: dict[str, str] = {}

    if workspace_secret:
        if getattr(workspace_secret, "google_api_key", None):
            env_vars["GOOGLE_API_KEY"] = workspace_secret.google_api_key
        if getattr(workspace_secret, "anthropic_api_key", None):
            env_vars["ANTHROPIC_API_KEY"] = workspace_secret.anthropic_api_key
        if getattr(workspace_secret, "google_cloud_project", None):
            env_vars["GOOGLE_CLOUD_PROJECT"] = workspace_secret.google_cloud_project

    if github_pat:
        env_vars["GITHUB_PAT"] = github_pat.token
        if getattr(github_pat, "username", None):
            env_vars["GITHUB_USERNAME"] = github_pat.username

    for mcp in (mcp_servers or []):
        if getattr(mcp, "catalog_key", None) == "jira":
            config = getattr(mcp, "config", {}) or {}
            for k, v in config.items():
                env_vars[k] = str(v)

    provider_spec = {"env": env_vars}
    return await client.provider_create(provider_spec)


async def create_provider_from_env(
    google_api_key: str,
    anthropic_api_key: str,
    github_pat: str,
    client=None,
) -> str:
    """Create a Provider from explicit credential values; returns provider_id."""
    if client is None:
        client = _get_client()
    env_vars: dict[str, str] = {}
    if google_api_key:
        env_vars["GOOGLE_API_KEY"] = google_api_key
    if anthropic_api_key:
        env_vars["ANTHROPIC_API_KEY"] = anthropic_api_key
    if github_pat:
        env_vars["GITHUB_PAT"] = github_pat
    ref = await client.provider_create({"env": env_vars})
    return ref.id


async def create_sandbox(
    image: str,
    provider_id: str | None,
    policy_yaml: str,
    client=None,
):
    """Create an OpenShell sandbox and wait for it to be ready.

    Returns the SandboxRef. Caller stores ref.name as session.sandbox_name.
    No PVCs are created — PVCs are gone in the OpenShell model.
    """
    if client is None:
        client = _get_client()
    spec: dict[str, Any] = {
        "image": image,
        "policy": policy_yaml,
    }
    if provider_id:
        spec["provider_id"] = provider_id
    ref = await client.create(spec)
    await client.wait_ready(ref.name)
    return ref


async def delete_sandbox(sandbox_name: str, client=None) -> None:
    """Delete an OpenShell sandbox.

    No PVC or K8s Secret cleanup needed — the Provider is cleaned up by
    the gateway and there are no PVCs in the OpenShell model.
    """
    if client is None:
        client = _get_client()
    await client.delete(sandbox_name)


async def clone_repos(sandbox_name: str, repos: list, client=None) -> None:
    """Clone git repos into /sandbox/ via exec (one exec call per repo)."""
    if client is None:
        client = _get_client()
    for repo in repos:
        target = f"/sandbox/{repo.local_path}"
        cmd = ["git", "clone", repo.url, target]
        await client.exec(sandbox_name, cmd)


async def write_agent_config(
    sandbox_name: str,
    tool_name: str,
    config_json: str,
    client=None,
) -> None:
    """Write agent config JSON to /sandbox/.config/{tool_name}/."""
    if client is None:
        client = _get_client()
    config_dir = f"/sandbox/.config/{tool_name}"
    config_path = f"{config_dir}/{tool_name}.json"
    script = f"mkdir -p {config_dir} && cat > {config_path} << 'EOCFG'\n{config_json}\nEOCFG"
    await client.exec(sandbox_name, ["sh", "-c", script])


async def write_agents_md(sandbox_name: str, content: str, client=None) -> None:
    """Write content to /sandbox/AGENTS.md."""
    if client is None:
        client = _get_client()
    script = f"cat > /sandbox/AGENTS.md << 'EOMD'\n{content}\nEOMD"
    await client.exec(sandbox_name, ["sh", "-c", script])


async def start_agent(sandbox_name: str, cmd: list[str], client=None) -> None:
    """Start the agent process inside the sandbox via exec."""
    if client is None:
        client = _get_client()
    await client.exec(sandbox_name, cmd)


async def exec_command(sandbox_name: str, cmd: list[str], client) -> Any:
    """Execute a command inside the sandbox and return the result (has .stdout, .stderr, .exit_code)."""
    return await client.exec(sandbox_name, cmd)
