#!/usr/bin/env python3

from requests_oauthlib import OAuth1

def handle_oauth1_auth(auth_config, variables, url, method):
    """Handle OAuth1 Authentication configuration."""
    cfg = {k["key"]: k["value"] for k in auth_config.get("oauth1", [])}
    auth = OAuth1(
        cfg.get("consumerKey"),
        cfg.get("consumerSecret"),
        cfg.get("token"),
        cfg.get("tokenSecret"),
        signature_method=cfg.get("signatureMethod", "HMAC-SHA1"),
    )
    return auth, {}, {} 