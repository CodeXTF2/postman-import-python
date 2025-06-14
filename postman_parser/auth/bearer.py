#!/usr/bin/env python3

def handle_bearer_auth(auth_config, variables, url, method):
    """Handle Bearer Token Authentication configuration."""
    token = next((d["value"] for d in auth_config.get("bearer", []) if d.get("key") == "token"), "")
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return None, headers, {} 