"""
Generate a JWT bearer token for the OpenShell gateway.

The token is RS256-signed with the swarmer-oidc key stored in the
'swarmer-oidc-signing-key' Kubernetes Secret (or read from a local file).

Usage:
  python3 scripts/openshell_gen_token.py [--days 30]
"""
import argparse
import sys
import time

ISSUER = "http://swarmer-oidc.openshell.svc.cluster.local"
AUDIENCE = "openshell"
KID = "swarmer-oidc-key-1"

# Embedded private key (generated during cluster setup — rotate via make openshell-gen-token)
_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9UELsfqpUanua
Q1inHlTmPmZg9g8moAEMkZ/j3eOpfwsqCmKOBnK5ShZ1Q6F6tVGA+cYjB2DEllZp
mNGvPLOQsUGA0TVNTctHlkNo4uCJJ3YPe8BePOaSr9ClymIKTA7e7HN0AZ+QEfFp
obIT8+cooXxIjn53Mq2oq1PQF5K6K2EwZQxrUUG0wxfp6gf6YUMxQ5VyL+VNyEwr
crvDUR5KLp386i2g+6oNfw2DIvsgnDkcbFpEodpig6KHkcXiJdGb8iQzk8H68UXf
YqCA7hvgIIhMmUeNAMgmZhrJTGCiqfE5Klg6gjahJ45mhj5eirpYBYhNw7GJX3H9
jjA4Q5ejAgMBAAECggEAFgk8KQQbdoUIiy3QqW9F6aEU0K+Dlvbj+F8REfiXkfi4
R3X6/9YvT3MYxyCOsNZfPNiWICixMmDfgR4pNjEmI68GVWTExBFMmrIaeaCDC2P9
AZNhknabTjLJ4ip7HAC7cGZsj/HKbX4xMB8CuADZhOi7K0Tu4pgTD8GVmXDNAv9r
R9G55Dr4WiXiHiaFeKXp8av2VtpIctytvc1kEytrkK1dlvoBpI3TPqCChwRsy4Bl
9pm1qgnuN7ZaZTgUHRPSdclCAqXc0nKzMVFQCVCuXn4OTz/Tj+XOGxNdTqSjFZu9
4me6jXvF8UehLD8s5tDVPsUmtIu2hoUHLewMyBIVhQKBgQDsn9lTJgfpMLv0k5PJ
nxhYwZomb1hzgLCuoLdhw+ElvZW0gNGUsXOXKpC+WGsTpY8GZGVRHS52XestXlQm
19VxPiGhW3qYV/N7B+TdnCZbOXXQ67EEYBaGeb2tIaKR64WZUxPufhMTCFBl3aEe
kpJtUraededNsSpCP8U4NSc63QKBgQDM0Kz0ybIYbpwYPr2dtP19gLq7jBMNBT92
ZY+/H7h/2nAyYPpKSiPkXAA9suZa9R0W1Pc816mcxvJKL+txQu3ZCelItRnm5Twf
Tr2gtc7cWP+gKaYbwO2/GlPhyI1o0u8jBcvhncA38sqPCv020W6b3NcgsBA8POXZ
C4PqZnK0fwKBgHu4EE8zQUuhmYSFbO4savRtNYYHDb5GeRq1GWzal+u9tnqMKAiQ
x5kwPkHnxQSeuatj7r18foCRFpfADEvK6eSt0bOmOvFQexPGytk7/aoQ3xL/SKy6
+MwS9yOAxJl7BX1nPLKj5KE85Zx9RvLPPBRA/Q7ZIrkyep/s69c5o2tZAoGAGgn9
szFhXxHQ7pQrbz1vbOFM3EM2uNUN+HN5DwdtYXPYB8+kgoVigsnfjfiMqMu44wo4
VJfmjHQOobft6vxjWNCVxBSiMmS6fBB6s0/p+MGn3ijtYWHp1/305COnNsh6dq1p
+kkgAvzvG7h98NY3hcFR6Gn55m6nmiyInOhhdOkCgYABaslwmQSC1lKO2juzW7zN
Uw8lPZUqFnP6YAJBd6I3gVjZRwGEB6ZWrhlOTGFoCuOg7Dy/SiFStkn3tPRKZWBu
XbjeJdCPnjqRqmUVfTZnKJUZ/uL2mqVYIisPLKkyyVvzh4ac/EF9QEbgLqryuZQu
q/Yt79Rz0AcEio9hqH1LSg==
-----END PRIVATE KEY-----"""


def main():
    parser = argparse.ArgumentParser(description="Generate OpenShell JWT bearer token")
    parser.add_argument("--days", type=int, default=30)
    args = parser.parse_args()

    try:
        import jwt
    except ImportError:
        sys.exit("Missing dependency: pyjwt\nRun: pip install pyjwt")

    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "swarmer",
        "iat": now,
        "exp": now + 86400 * args.days,
        # OpenShell reads roles from realm_access.roles (Keycloak format, default roles_claim)
        "realm_access": {"roles": ["openshell-admin"]},
    }
    token = jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256", headers={"kid": KID})
    print(token)


if __name__ == "__main__":
    main()
