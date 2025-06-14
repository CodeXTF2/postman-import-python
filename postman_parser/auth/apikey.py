#!/usr/bin/env python3

def handle_apikey_auth(auth_config, variables, url, method):
    """Handle API Key Authentication configuration."""
    cfg = {k["key"]: k["value"] for k in auth_config.get("apikey", [])}
    k, v, loc = cfg.get("key"), cfg.get("value"), cfg.get("in", "header")
    headers, params = {}, {}
    
    if loc == "header":
        headers[k] = v
    elif loc == "query":
        params[k] = v
    elif loc == "cookie":
        headers["Cookie"] = f"{k}={v}"
    
    return None, headers, params 