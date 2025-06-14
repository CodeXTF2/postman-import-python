#!/usr/bin/env python3

import base64

def handle_ntlm_auth(auth_config, variables, url, method):
    """Handle NTLM Authentication configuration."""
    cfg = {k["key"]: k["value"] for k in auth_config.get("ntlm", [])}
    user = cfg.get("username", "")
    domain = cfg.get("domain", "")
    ntlm_bytes = b"NTLMSSP\x00\x03\x00\x00\x00" + user.encode("utf-8")
    headers = {
        "Authorization": "NTLM " + base64.b64encode(ntlm_bytes).decode()
    }
    return None, headers, {} 