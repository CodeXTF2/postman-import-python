#!/usr/bin/env python3

from requests_aws4auth import AWS4Auth

def handle_aws_auth(auth_config, variables, url, method):
    """Handle AWS Signature V4 Authentication configuration."""
    cfg = {k["key"]: k["value"] for k in auth_config.get("awssigv4", []) or 
           auth_config.get("awsv4", []) or auth_config.get("aws", [])}
    auth = AWS4Auth(
        cfg.get("accessKey"),
        cfg.get("secretKey"),
        cfg.get("region", "us-east-1"),
        cfg.get("service", "execute-api"),
    )
    return auth, {}, {} 