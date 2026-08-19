"""
Seed (or rotate) the encrypted OIDC refresh token Swarmer uses to talk to a
remote/hosted OpenShell gateway (ACM-41655, OPENSHELL_AUTH_MODE=oidc).

Swarmer never performs the interactive OIDC login flow itself — the refresh
token must come from somewhere that already completed it, e.g.:

    openshell gateway login <name>

which writes ~/.config/openshell/gateways/<name>/oidc_token.json on the
machine you ran it from. This script reads that file (or an explicit
--refresh-token) ONCE and writes the token encrypted into Swarmer's own DB
(openshell_gateway_credentials table) — never to a file or log — matching
the repo's "encrypted database over Kubernetes objects" policy.

Run this against the same DATABASE_URL / SWARMER_SECRET_KEY (or
secret_key_file) the deployed Swarmer instance uses. For a Swarmer running as
a remote K8s pod, that means running this script via `kubectl exec` INTO the
running pod — see `make openshell-oidc-seed GATEWAY=<name>`, which automates
extracting the token locally and piping it in over stdin (so it never
appears in `kubectl exec` argv / shell history / K8s audit logs). For local
dev, run it directly against data/swarmer.db.

No pod restart is required: swarmer.openshell_oidc.OidcGatewayAuth lazily
re-reads the DB the next time an OpenShell API call needs a token, so a
`kubectl exec` seed/re-seed into a running pod takes effect on the very next
call.

Usage:
    # Convenience: read the local `openshell` CLI's cached token for gateway "swarm"
    python3 scripts/openshell_seed_oidc_credential.py --from-cli-gateway swarm

    # Piped via stdin (avoids the secret appearing in argv) — used by
    # `make openshell-oidc-seed` for the kubectl exec remote-pod flow
    echo "$TOKEN" | python3 scripts/openshell_seed_oidc_credential.py --refresh-token-stdin

    # Explicit token as an argument (fine for local dev; avoid for shared shells)
    python3 scripts/openshell_seed_oidc_credential.py --refresh-token "$TOKEN"
"""
import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _read_cli_gateway_token(gateway_name: str) -> tuple[str, str, int | None]:
    """Return (refresh_token, access_token, expires_at) from the local
    `openshell` CLI's cached bundle for the given gateway name."""
    path = Path.home() / ".config" / "openshell" / "gateways" / gateway_name / "oidc_token.json"
    if not path.exists():
        sys.exit(
            f"No cached OIDC token found at {path}. "
            f"Run 'openshell gateway login {gateway_name}' first."
        )
    bundle = json.loads(path.read_text())
    refresh_token = bundle.get("refresh_token", "")
    if not refresh_token:
        sys.exit(f"{path} has no refresh_token.")
    return refresh_token, bundle.get("access_token", ""), bundle.get("expires_at")


async def _seed(refresh_token: str, access_token: str, expires_at: int | None) -> None:
    from sqlalchemy import select

    from swarmer.config import settings
    from swarmer.crypto import init_crypto
    from swarmer.database import create_tables, get_db, init_db, migrate_db
    from swarmer.models.openshell_gateway_credential import OpenshellGatewayCredential

    init_crypto(settings.secret_key_file)
    init_db(settings.database_url)
    await create_tables()
    await migrate_db()

    async for db in get_db():
        row = (await db.execute(select(OpenshellGatewayCredential).limit(1))).scalar_one_or_none()
        if row is None:
            row = OpenshellGatewayCredential()
            db.add(row)
        row.refresh_token = refresh_token
        row.access_token = access_token
        row.access_token_expires_at = (
            datetime.fromtimestamp(expires_at, tz=timezone.utc).replace(tzinfo=None)
            if expires_at
            else None
        )
        await db.commit()
        break

    print("✓ OpenShell OIDC credential seeded in the database.")
    print("  A running Swarmer instance picks this up on its next OpenShell API")
    print("  call — no restart required (see swarmer/openshell_oidc.py).")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--from-cli-gateway",
        metavar="NAME",
        help="Read the refresh token from the local `openshell` CLI's cache "
        "for this gateway name (e.g. 'swarm'). Convenience for bootstrap only.",
    )
    src.add_argument("--refresh-token", help="Refresh token value, supplied directly.")
    src.add_argument(
        "--refresh-token-stdin",
        action="store_true",
        help="Read the refresh token from stdin (one line, trailing whitespace stripped). "
        "Avoids the secret appearing in argv/shell history/K8s audit logs — used by "
        "`make openshell-oidc-seed` for the kubectl exec remote-pod flow.",
    )
    parser.add_argument(
        "--access-token", default="", help="Optional cached access token (avoids one extra refresh)."
    )
    parser.add_argument(
        "--expires-at", type=int, default=None, help="Optional access token expiry (Unix epoch seconds)."
    )
    args = parser.parse_args()

    if args.from_cli_gateway:
        refresh_token, access_token, expires_at = _read_cli_gateway_token(args.from_cli_gateway)
    elif args.refresh_token_stdin:
        refresh_token = sys.stdin.readline().strip()
        if not refresh_token:
            sys.exit("No refresh token received on stdin.")
        access_token, expires_at = args.access_token, args.expires_at
    else:
        refresh_token, access_token, expires_at = args.refresh_token, args.access_token, args.expires_at

    asyncio.run(_seed(refresh_token, access_token, expires_at))


if __name__ == "__main__":
    main()
