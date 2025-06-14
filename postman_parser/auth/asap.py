#!/usr/bin/env python3

import json
import time
import jwt

def handle_asap_auth(auth_config, variables, url, method):
    """Handle ASAP Authentication configuration."""
    cfg = {k["key"]: k["value"] for k in auth_config.get("asap", [])}
    headers = {}

    supplied = next(
        (d["value"] for d in auth_config.get("asap", [])
         if d.get("key") == "token" and d["value"]), ""
    )
    if supplied:
        headers["Authorization"] = f"Bearer {supplied}"
        return None, headers, {}

    iss = cfg.get("issuer") or variables.get("asapIssuer")
    aud = cfg.get("audience") or variables.get("asapAudience")

    with open("config.json") as f:
        config = json.load(f)
        kid = next(iter(config["asap"]["public_keys"].keys()), None)

    if not kid:
        raise ValueError(
            "ASAP: missing key-ID. Please set the Postman variable "
            "`asap-key-id` (or add `kid` in the auth block) to match your server's public key map."
        )

    priv = (
        cfg.get("privateKey") or cfg.get("private_key")
        or variables.get("asapPrivateKey", "")
    ).strip()
    if not priv:
        raise ValueError(
            "ASAP: no private key found. "
            "Set the Postman variable `asapPrivateKey` to your PEM-formatted key."
        )

    now = int(time.time())
    payload = {
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + 5 * 60,
    }

    token = jwt.encode(
        payload,
        priv,
        algorithm="RS256",
        headers={"kid": kid},
    )
    if isinstance(token, bytes):
        token = token.decode()

    headers["Authorization"] = f"Bearer {token}"
    return None, headers, {} 