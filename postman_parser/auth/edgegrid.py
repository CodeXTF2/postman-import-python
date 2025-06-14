#!/usr/bin/env python3

from urllib.parse import urlparse
from akamai.edgegrid import EdgeGridAuth

def handle_edgegrid_auth(auth_config, variables, url, method):
    """Handle Akamai EdgeGrid Authentication configuration."""
    cfg = {k["key"]: k["value"] for k in auth_config.get("edgegrid", [])}
    auth = EdgeGridAuth(
        cfg.get("clientToken"),
        cfg.get("clientSecret"),
        cfg.get("accessToken"),
        max_body=int(cfg.get("maxBody", 1024)),
    )
    headers = {}
    host = urlparse(url).hostname
    if host:
        headers["Host"] = host
    return auth, headers, {} 