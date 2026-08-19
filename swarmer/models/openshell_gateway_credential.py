from datetime import datetime

from sqlalchemy import DateTime, Text, func
from sqlalchemy.orm import Mapped, mapped_column

import swarmer.crypto as crypto
from swarmer.database import Base


class OpenshellGatewayCredential(Base):
    """Singleton row storing the OIDC token bundle for the global remote
    OpenShell gateway (ACM-41655).

    Only one row is expected — today Swarmer talks to a single global
    OpenShell gateway (e.g. an in-cluster mTLS gateway, or a remote
    OIDC-authenticated gateway like the "swarm" gateway registered with the
    `openshell` CLI). Per-workspace gateways are tracked separately
    (ACM-41656) and are out of scope here.

    Populated out-of-band via scripts/openshell_seed_oidc_credential.py (the
    refresh token comes from `openshell gateway login`, not from Swarmer
    itself — Swarmer never performs the interactive OIDC login flow) and kept
    fresh at runtime by swarmer.openshell_oidc, which refreshes against the
    IdP's token endpoint and writes rotated bundles back here.

    Both tokens are encrypted via crypto.encrypt()/decrypt() per the repo's
    Sensitive Data Policy — never stored or logged in plaintext.
    """

    __tablename__ = "openshell_gateway_credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    refresh_token_enc: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    access_token_enc: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    access_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )

    @property
    def refresh_token(self) -> str:
        return crypto.decrypt(self.refresh_token_enc)

    @refresh_token.setter
    def refresh_token(self, value: str) -> None:
        self.refresh_token_enc = crypto.encrypt(value or "")

    @property
    def access_token(self) -> str:
        return crypto.decrypt(self.access_token_enc)

    @access_token.setter
    def access_token(self, value: str) -> None:
        self.access_token_enc = crypto.encrypt(value or "")
