import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import respx

from swarmer.crypto import init_crypto
from swarmer.models.workspace import Workspace
from swarmer.models.workspace_gateway import WorkspaceGateway
from swarmer.openshell_client import (
    GatewayConfig,
    resolve_gateway_config,
    probe_gateway_connectivity,
)
from swarmer.openshell_oidc import OidcGatewayAuth


@pytest.fixture(autouse=True)
def init_test_crypto(tmp_path):
    key_file = tmp_path / "secret.key"
    init_crypto(str(key_file))


@respx.mock
def test_oidc_auth_refresh_flow():
    issuer = "https://keycloak.example.com/realms/test"
    client_id = "test-client"

    # Mock discovery
    respx.get(f"{issuer}/.well-known/openid-configuration").respond(
        200,
        json={"issuer": issuer, "token_endpoint": f"{issuer}/protocol/openid-connect/token"},
    )

    # Mock token endpoint
    respx.post(f"{issuer}/protocol/openid-connect/token").respond(
        200,
        json={
            "access_token": "new-access-token",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 300,
        },
    )

    auth = OidcGatewayAuth(issuer=issuer, client_id=client_id, workspace_id=1)
    auth.seed(refresh_token="initial-refresh-token")

    token = auth.current_access_token()
    assert token == "new-access-token"
    assert auth._bundle["refresh_token"] == "rotated-refresh-token"
    assert auth._bundle["access_token"] == "new-access-token"


@pytest.mark.asyncio
async def test_resolve_gateway_config_default():
    cfg = await resolve_gateway_config(None)
    assert cfg.auth_mode in ("default", "mtls", "bearer")


@pytest.mark.asyncio
async def test_resolve_gateway_config_custom_workspace():
    ws = Workspace(id=42, display_name="Custom WS", namespace="custom-ws")
    gw = WorkspaceGateway(
        workspace_id=42,
        gateway_url="https://gw-42.example.com:443",
        auth_mode="bearer",
    )
    gw.bearer_token = "secret-bearer-42"
    ws.gateway = gw

    cfg = await resolve_gateway_config(ws)
    assert cfg.gateway_url == "https://gw-42.example.com:443"
    assert cfg.auth_mode == "bearer"
    assert cfg.bearer_token == "secret-bearer-42"
    assert cfg.workspace_id == 42


@pytest.mark.asyncio
async def test_probe_gateway_connectivity_mock():
    cfg = GatewayConfig(gateway_url="https://gw.example.com", auth_mode="none")
    mock_client = MagicMock()
    mock_client.list_sandboxes.return_value = ["sb-1", "sb-2"]

    with patch("swarmer.openshell_client.get_client_for_config", return_value=mock_client):
        res = await probe_gateway_connectivity(cfg)
        assert res["status"] == "ok"
        assert res["sandboxes_count"] == 2
