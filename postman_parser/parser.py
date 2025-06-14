#!/usr/bin/env python3

import json
import re
from urllib.parse import urlparse

from .auth import (
    handle_basic_auth,
    handle_digest_auth,
    handle_bearer_auth,
    handle_apikey_auth,
    handle_oauth1_auth,
    handle_oauth2_auth,
    handle_hawk_auth,
    handle_ntlm_auth,
    handle_edgegrid_auth,
    handle_asap_auth,
    handle_aws_auth,
)

def deep_replace(obj, mapping):
    """Replace {{var}} placeholders recursively using mapping dict."""
    if isinstance(obj, str):
        return re.sub(r"{{\s*([^}]+?)\s*}}",
                      lambda m: str(mapping.get(m.group(1), m.group(0))), obj)
    if isinstance(obj, list):
        return [deep_replace(i, mapping) for i in obj]
    if isinstance(obj, dict):
        return {k: deep_replace(v, mapping) for k, v in obj.items()}
    return obj

def ParsePostmanJSON(collection_json):
    variables = {v["key"]: v.get("value", "") for v in collection_json.get("variable", [])}
    out = []

    for item in collection_json.get("item", []):
        raw = item.get("request", {})
        req = deep_replace(raw, variables)

        name, desc = item.get("name", ""), raw.get("description", "")
        method = req.get("method", "GET").lower()
        url = req.get("url", {}).get("raw", "")

        headers, params, auth = {}, {}, None

        a = req.get("auth", {}) or {}
        typ = a.get("type", "").lower()

        auth_handlers = {
            "basic": handle_basic_auth,
            "digest": handle_digest_auth,
            "bearer": handle_bearer_auth,
            "apikey": handle_apikey_auth,
            "oauth1": handle_oauth1_auth,
            "oauth2": handle_oauth2_auth,
            "hawk": handle_hawk_auth,
            "ntlm": handle_ntlm_auth,
            "edgegrid": handle_edgegrid_auth,
            "asap": handle_asap_auth,
            "awssigv4": handle_aws_auth,
            "awsv4": handle_aws_auth,
            "aws": handle_aws_auth,
        }

        if typ in auth_handlers:
            auth, headers, params = auth_handlers[typ](a, variables, url, method)

        data = json_data = None
        body = req.get("body", {}) or {}
        mode = body.get("mode")

        if mode == "raw":
            raw = body.get("raw", "")
            if body.get("options", {}).get("raw", {}).get("language") == "json":
                try:
                    json_data = json.loads(raw)
                except ValueError:
                    data = raw
            else:
                data = raw
        elif mode == "urlencoded":
            data = {i["key"]: i["value"] for i in body.get("urlencoded", [])}
        elif mode == "formdata":
            data = {i["key"]: i["value"] for i in body.get("formdata", [])}

        spec = {"method": method, "url": url, "headers": headers, "params": params}
        if auth:
            spec["auth"] = auth
        if data:
            spec["data"] = data
        if json_data:
            spec["json"] = json_data

        out.append({"name": name, "description": desc, "request": spec})

    return out 