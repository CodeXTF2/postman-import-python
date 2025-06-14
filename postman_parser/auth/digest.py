#!/usr/bin/env python3

from requests.auth import HTTPDigestAuth

def handle_digest_auth(auth_config, variables, url, method):
    """Handle Digest Authentication configuration."""
    cfg = {k["key"]: k["value"] for k in auth_config.get("digest", [])}
    auth = HTTPDigestAuth(cfg.get("username"), cfg.get("password"))
    return auth, {}, {} 