#!/usr/bin/env python3

from requests.auth import HTTPBasicAuth

def handle_basic_auth(auth_config, variables, url, method):
    """Handle Basic Authentication configuration."""
    cfg = {k["key"]: k["value"] for k in auth_config.get("basic", [])}
    auth = HTTPBasicAuth(cfg.get("username"), cfg.get("password"))
    return auth, {}, {} 