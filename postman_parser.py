#!/usr/bin/env python3

import json, re, time, base64
from urllib.parse import urlparse

import jwt
from requests.auth     import HTTPBasicAuth, HTTPDigestAuth
from requests_oauthlib import OAuth1
from requests_aws4auth import AWS4Auth
from akamai.edgegrid   import EdgeGridAuth
from mohawk            import Sender


# ───────────────────────── helpers ─────────────────────────
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


# ───────────────────────── main routine ────────────────────
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

        # ───── auth handling ──────────────────────────────────
        a = req.get("auth", {}) or {}
        typ = a.get("type", "").lower()

        if typ == "basic":
            cfg = {k["key"]: k["value"] for k in a.get("basic", [])}
            auth = HTTPBasicAuth(cfg.get("username"), cfg.get("password"))

        elif typ == "digest":
            cfg = {k["key"]: k["value"] for k in a.get("digest", [])}
            auth = HTTPDigestAuth(cfg.get("username"), cfg.get("password"))

        elif typ == "bearer":
            token = next((d["value"] for d in a.get("bearer", []) if d.get("key") == "token"), "")
            if token:
                headers["Authorization"] = f"Bearer {token}"

        elif typ == "apikey":
            cfg = {k["key"]: k["value"] for k in a.get("apikey", [])}
            k, v, loc = cfg.get("key"), cfg.get("value"), cfg.get("in", "header")
            if loc == "header":
                headers[k] = v
            elif loc == "query":
                params[k] = v
            elif loc == "cookie":
                headers["Cookie"] = f"{k}={v}"

        elif typ == "oauth1":
            cfg = {k["key"]: k["value"] for k in a.get("oauth1", [])}
            auth = OAuth1(
                cfg.get("consumerKey"),
                cfg.get("consumerSecret"),
                cfg.get("token"),
                cfg.get("tokenSecret"),
                signature_method=cfg.get("signatureMethod", "HMAC-SHA1"),
            )

        elif typ == "oauth2":
            cfg = {k["key"]: k["value"] for k in a.get("oauth2", [])}
            # token precedence: auth block → variables["oauth2Token"]
            tok = cfg.get("accessToken") or cfg.get("token") or variables.get("oauth2Token", "")
            if tok:
                target = cfg.get("addTokenTo", "header").lower()
                if target == "query":
                    params["access_token"] = tok
                elif target == "cookie":
                    headers["Cookie"] = f"access_token={tok}"
                else:  # default - header
                    headers["Authorization"] = f"Bearer {tok}"

        elif typ == "hawk":
            cfg = {k["key"]: k["value"] for k in a.get("hawk", [])}
            creds = {
                "id": cfg.get("authId"),
                "key": cfg.get("authKey"),
                "algorithm": cfg.get("algorithm", "sha256"),
            }
            sender = Sender(creds, url, method.upper(), content=b"", content_type="text/plain")
            headers["Authorization"] = sender.request_header
            headers.setdefault("Content-Type", "text/plain")

        elif typ == "ntlm":
            cfg = {k["key"]: k["value"] for k in a.get("ntlm", [])}
            user = cfg.get("username", "")
            domain = cfg.get("domain", "")
            # The demo server only needs the username to appear in a Type-3 packet.
            # Build: "NTLMSSP\0" + 0x03 + 3 padding bytes + username bytes
            ntlm_bytes = b"NTLMSSP\x00\x03\x00\x00\x00" + user.encode("utf-8")
            headers["Authorization"] = "NTLM " + base64.b64encode(ntlm_bytes).decode()

        elif typ == "edgegrid":
            cfg = {k["key"]: k["value"] for k in a.get("edgegrid", [])}
            auth = EdgeGridAuth(
                cfg.get("clientToken"),
                cfg.get("clientSecret"),
                cfg.get("accessToken"),
                max_body=int(cfg.get("maxBody", 1024)),
            )
            host = urlparse(url).hostname
            if host:
                headers.setdefault("Host", host)

        elif typ == "asap":
            cfg = {k["key"]: k["value"] for k in a.get("asap", [])}

            supplied = next(
                (d["value"] for d in a.get("asap", [])
                 if d.get("key") == "token" and d["value"]), ""
            )
            if supplied:
                headers["Authorization"] = f"Bearer {supplied}"
                continue

            iss = cfg.get("issuer")   or variables.get("asapIssuer")
            aud = cfg.get("audience") or variables.get("asapAudience")

            # Get the first key ID from the public_keys map in config
            with open("config.json") as f:
                config = json.load(f)
                kid = next(iter(config["asap"]["public_keys"].keys()), None)

            if not kid:
                raise ValueError(
                    "ASAP: missing key-ID.  Please set the Postman variable "
                    "`asap-key-id` (or add `kid` in the auth block) to match your server's public key map."
                )

            priv = (
                cfg.get("privateKey") or cfg.get("private_key")
                or variables.get("asapPrivateKey", "")
            ).strip()
            if not priv:
                raise ValueError(
                    "ASAP: no private key found.  "
                    "Set the Postman variable `asapPrivateKey` to your PEM-formatted key."
                )

            now = int(time.time())
            payload = {
                "iss": iss,
                "aud": aud,
                "iat": now,
                "exp": now + 5 * 60,   # 5-minute lifetime
            }

            token = jwt.encode(
                payload,
                priv,
                algorithm="RS256",
                headers={"kid": kid},
            )
            if isinstance(token, bytes):
                token = token.decode()

            headers["Authorization"] = f"Bearer {token}"

        elif typ in ("awssigv4", "awsv4", "aws"):
            cfg = {k["key"]: k["value"] for k in a.get("awssigv4", []) or a.get("awsv4", []) or a.get("aws", [])}
            auth = AWS4Auth(
                cfg.get("accessKey"),
                cfg.get("secretKey"),
                cfg.get("region", "us-east-1"),
                cfg.get("service", "execute-api"),
            )

        # ───── body handling ─────────────────────────────────────
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

        # assemble
        spec = {"method": method, "url": url, "headers": headers, "params": params}
        if auth:
            spec["auth"] = auth
        if data:
            spec["data"] = data
        if json_data:
            spec["json"] = json_data

        out.append({"name": name, "description": desc, "request": spec})

    return out
