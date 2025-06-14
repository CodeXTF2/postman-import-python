#!/usr/bin/env python3

def handle_oauth2_auth(auth_config, variables, url, method):
    """Handle OAuth2 Authentication configuration."""
    cfg = {k["key"]: k["value"] for k in auth_config.get("oauth2", [])}
    tok = cfg.get("accessToken") or cfg.get("token") or variables.get("oauth2Token", "")
    headers, params = {}, {}
    
    if tok:
        target = cfg.get("addTokenTo", "header").lower()
        if target == "query":
            params["access_token"] = tok
        elif target == "cookie":
            headers["Cookie"] = f"access_token={tok}"
        else:
            headers["Authorization"] = f"Bearer {tok}"
    
    return None, headers, params 