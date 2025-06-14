#!/usr/bin/env python3

from mohawk import Sender

def handle_hawk_auth(auth_config, variables, url, method):
    """Handle Hawk Authentication configuration."""
    cfg = {k["key"]: k["value"] for k in auth_config.get("hawk", [])}
    creds = {
        "id": cfg.get("authId"),
        "key": cfg.get("authKey"),
        "algorithm": cfg.get("algorithm", "sha256"),
    }
    sender = Sender(creds, url, method.upper(), content=b"", content_type="text/plain")
    headers = {
        "Authorization": sender.request_header,
        "Content-Type": "text/plain"
    }
    return None, headers, {} 