#!/usr/bin/env python3


import base64
import hashlib
import json
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, Tuple

import urllib.parse
import jwt
from flask import Flask, jsonify, make_response, request
from flask_httpauth import HTTPBasicAuth, HTTPDigestAuth
from oauthlib.oauth1 import RequestValidator, SignatureOnlyEndpoint
from termcolor import colored
from werkzeug.exceptions import Unauthorized

# -----------------------------------------------------------------------------
# Test‑result tracker (unchanged)
# -----------------------------------------------------------------------------

class TestTracker:
    def __init__(self):
        self.reset()

    def reset(self):
        self.test_id = None
        self.results = defaultdict(lambda: {"success": 0, "fail": 0})
        self.start_time = None
        self.end_time = None

    def start_test(self):
        self.reset()
        self.test_id = secrets.token_hex(8)
        self.start_time = time.time()
        return self.test_id

    def end_test(self):
        self.end_time = time.time()
        return self._render()

    def record_result(self, auth_type: str, success: bool):
        key = "success" if success else "fail"
        self.results[auth_type][key] += 1

    def _render(self):
        if not self.test_id:
            return "No test in progress"
        dur = self.end_time - self.start_time
        out = [
            f"\n=== Test Results (ID: {self.test_id}) ===",
            f"Duration: {dur:.2f}s",
            "\nAuth Type Results:",
        ]
        overall = True
        for auth, cnt in self.results.items():
            ok = cnt == {"success": 1, "fail": 1}
            overall &= ok
            mark = "✓" if ok else "✗"
            line = f"{auth} {mark}: Success {cnt['success']} / Fail {cnt['fail']}"
            out.append(colored(line, "green" if ok else "red"))
        out.append("\nOverall: " + ("PASSED" if overall else colored("FAILED", "red")))
        return "\n".join(out)


test_tracker = TestTracker()

# -----------------------------------------------------------------------------
# Configuration loader (unchanged key names)
# -----------------------------------------------------------------------------

CONFIG_PATH = "config.json"
if not os.path.exists(CONFIG_PATH):
    raise RuntimeError("config.json missing—please create it first")
with open(CONFIG_PATH) as f:
    config = json.load(f)

# -----------------------------------------------------------------------------
# Flask setup
# -----------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

basic_auth = HTTPBasicAuth()
digest_auth = HTTPDigestAuth()

# -----------------------------------------------------------------------------
# BASIC AUTH (unchanged)
# -----------------------------------------------------------------------------

@basic_auth.verify_password
def verify_basic(u, p):
    ok = u == config["basic"]["username"] and p == config["basic"]["password"]
    test_tracker.record_result("Basic Auth", ok)
    return u if ok else None


@app.route("/basic-auth")
@basic_auth.login_required
def basic_route():
    return jsonify({"message": "Hello, Basic Auth!", "user": basic_auth.current_user()})

# -----------------------------------------------------------------------------
# DIGEST AUTH (unchanged)
# -----------------------------------------------------------------------------

@digest_auth.get_password
def get_digest_pw(u):
    ok = u == config["digest"]["username"]
    test_tracker.record_result("Digest Auth", ok)
    return config["digest"]["password"] if ok else None


@app.route("/digest-auth")
@digest_auth.login_required
def digest_route():
    return jsonify({"message": "Hello, Digest Auth!", "user": digest_auth.current_user()})

# -----------------------------------------------------------------------------
# API‑KEY (unchanged)
# -----------------------------------------------------------------------------

@app.route("/api-key")
def api_key_route():
    key = request.headers.get("X-API-Key", "")
    ok = key == config["api_key"]
    test_tracker.record_result("API Key", ok)
    if not ok:
        return jsonify({"error": "Invalid / missing API key"}), 401
    return jsonify({"message": "Hello, API Key!"})

# -----------------------------------------------------------------------------
# JWT (unchanged)
# -----------------------------------------------------------------------------

@app.route("/jwt-token")
def jwt_token():
    return jsonify({"token": config["jwt"]["token"]})


@app.route("/jwt")
def jwt_route():
    hdr = request.headers.get("Authorization", "")
    if not hdr.startswith("Bearer "):
        test_tracker.record_result("JWT", False)
        return jsonify({"error": "Missing Bearer token"}), 401
    token = hdr.split()[1]
    try:
        payload = jwt.decode(token, config["jwt"]["secret"], algorithms=["HS256"])
        test_tracker.record_result("JWT", True)
        return jsonify({"message": "Hello, JWT Auth!", "payload": payload})
    except jwt.InvalidTokenError:
        test_tracker.record_result("JWT", False)
        return jsonify({"error": "Invalid JWT token"}), 401

# -----------------------------------------------------------------------------
# OAuth2 client‑credentials (unchanged)
# -----------------------------------------------------------------------------

@app.route("/protected-oauth2")
def protected_oauth2():
    hdr = request.headers.get("Authorization", "")
    ok = hdr == f"Bearer {config['oauth2']['token']}"
    test_tracker.record_result("OAuth2", ok)
    if not ok:
        return jsonify({"error": "Invalid / missing OAuth2 token"}), 401
    return jsonify({"message": "Hello, OAuth2 Auth!"})

# -----------------------------------------------------------------------------
# ** OAuth 1
# -----------------------------------------------------------------------------
def _parse_oauth_header(hdr: str) -> dict[str, str]:
    """Parse an OAuth1 Authorization header into a dict."""
    if not hdr.startswith("OAuth "):
        return {}
    params = {}
    for part in hdr[6:].split(","):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            params[k] = urllib.parse.unquote(v.strip('"'))
    return params

@app.route("/protected-oauth1")
def protected_oauth1():
    params = _parse_oauth_header(request.headers.get("Authorization", ""))
    ok = params.get("oauth_token") == config["oauth1"]["token"]
    test_tracker.record_result("OAuth1 protected", ok)
    if not ok:
        return jsonify({"error": "Invalid / missing OAuth1 token"}), 401
    return jsonify({"message": "Hello, OAuth1 Auth!"})

# -----------------------------------------------------------------------------
# ** ASAP – FIXED to RS256 **
# -----------------------------------------------------------------------------

ASAP_CFG = config["asap"]
_public_keys: Dict[str, str] = {}


def _get_public_key(kid: str) -> str:
    """Get the public key for a given key ID."""
    if kid in _public_keys:
        return _public_keys[kid]
    try:
        pem = ASAP_CFG["public_keys"][kid]
    except KeyError:
        raise Unauthorized(f"Unknown kid: {kid}")
    _public_keys[kid] = pem
    return pem


def utc_now() -> int:
    """Get current UTC timestamp in seconds."""
    return int(datetime.now(timezone.utc).timestamp())


def _qsh() -> str:
    """Calculate the ASAP QSH (Query String Hash) per spec."""
    base = f"{request.method.upper()}&{request.path}&{request.query_string.decode()}"
    return hashlib.sha256(base.encode()).hexdigest()


@app.route("/asap-auth")
def asap_route():
    hdr = request.headers.get("Authorization", "")
    if not hdr.startswith("Bearer "):
        test_tracker.record_result("ASAP", False)
        return jsonify({"error": "Missing Bearer token"}), 401

    token = hdr.split()[1]
    try:
        # Get unverified header to extract kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            test_tracker.record_result("ASAP", False)
            return jsonify({"error": "Missing kid header"}), 401

        # Verify token with RS256
        payload = jwt.decode(
            token,
            _get_public_key(kid),
            algorithms=["RS256"],
            audience=ASAP_CFG["audience"],
            issuer=ASAP_CFG["issuer"],
        )

        # Enforce iat/exp window (spec: <=30 min lifetime)
        now = utc_now()
        if not (payload["iat"] <= now <= payload["exp"]):
            raise jwt.InvalidTokenError("Token expired or not yet valid")


        # Optional QSH check if present
        if "qsh" in payload and payload["qsh"] != _qsh():
            raise jwt.InvalidTokenError("QSH mismatch")

    except (jwt.InvalidTokenError, KeyError) as e:
        test_tracker.record_result("ASAP", False)
        return jsonify({"error": f"Invalid ASAP token: {e}"}), 401

    test_tracker.record_result("ASAP", True)
    return jsonify({"message": "Hello, ASAP Auth!", "claims": payload})

# -----------------------------------------------------------------------------
# HAWK (unchanged)
# -----------------------------------------------------------------------------

from mohawk import Receiver  # imported late to keep original order

@app.route("/hawk", methods=["GET", "POST"])
def hawk_route():
    def lookup(_id):
        if _id == config["hawk"]["id"]:
            return {"id": _id, "key": config["hawk"]["key"], "algorithm": "sha256"}
    hdr = request.headers.get("Authorization", "")
    try:
        Receiver(
            lookup,
            hdr,
            request.url,
            request.method,
            request.get_data() or b"",
            request.headers.get("Content-Type", ""),
        )
        test_tracker.record_result("Hawk", True)
        return jsonify({"message": "Hello, Hawk Auth!"})
    except Exception:
        test_tracker.record_result("Hawk", False)
        return jsonify({"error": "Invalid Hawk credentials"}), 401

# -----------------------------------------------------------------------------
# NTLM (unchanged)
# -----------------------------------------------------------------------------

@app.route("/ntlm-auth")
def ntlm_route():
    hdr = request.headers.get("Authorization", "")
    nt = config["ntlm"]

    if not hdr.startswith("NTLM "):
        resp = make_response(jsonify({"error": "NTLM negotiate"}), 401)
        resp.headers["WWW-Authenticate"] = "NTLM"
        test_tracker.record_result("NTLM", False)
        return resp

    ntlm_message = base64.b64decode(hdr[5:])
    msg_type = ntlm_message[8]

    if msg_type == 1:
        challenge = b"NTLMSSP\x00\x02\x00\x00\x00" + b"\x00" * 24
        resp = make_response(jsonify({"error": "NTLM challenge"}), 401)
        resp.headers["WWW-Authenticate"] = f"NTLM {base64.b64encode(challenge).decode()}"
        test_tracker.record_result("NTLM", False)
        return resp
    elif msg_type == 3:
        if nt["username"].encode() in ntlm_message:
            test_tracker.record_result("NTLM", True)
            return jsonify({"message": "Hello, NTLM Auth!"})
        test_tracker.record_result("NTLM", False)
        return jsonify({"error": "Invalid NTLM credentials"}), 401
    test_tracker.record_result("NTLM", False)
    return jsonify({"error": "Invalid NTLM message type"}), 401

# -----------------------------------------------------------------------------
# Akamai EdgeGrid (unchanged)
# -----------------------------------------------------------------------------

@app.route("/akamai-edgegrid")
def edgegrid_route():
    hdr = request.headers.get("Authorization", "")
    eg = config["edgegrid"]
    ok = (
        hdr.startswith("EG1-HMAC-SHA256")
        and f"client_token={eg['client_token']}" in hdr
        and f"access_token={eg['access_token']}" in hdr
        and "signature=" in hdr
    )
    test_tracker.record_result("EdgeGrid", ok)
    if not ok:
        return jsonify({"error": "Invalid EdgeGrid header"}), 401
    return jsonify({"message": "Hello, Akamai EdgeGrid Auth!"})

# -----------------------------------------------------------------------------
# AWS Signature V4 (unchanged)
# -----------------------------------------------------------------------------

@app.route("/aws-sigv4")
def aws_sigv4_route():
    hdr = request.headers.get("Authorization", "")
    aws = config["aws"]
    if not hdr.startswith("AWS4-HMAC-SHA256"):
        test_tracker.record_result("AWS SigV4", False)
        return jsonify({"error": "Missing AWS4-HMAC-SHA256"}), 401

    cred_ok = f"Credential={aws['access_key']}/" in hdr
    has_sig = "Signature=" in hdr and "SignedHeaders=" in hdr
    ok = cred_ok and has_sig
    test_tracker.record_result("AWS SigV4", ok)
    if not ok:
        return jsonify({"error": "Invalid AWS SigV4 header"}), 401
    return jsonify({"message": "Hello, AWS SigV4 Auth!"})

# -----------------------------------------------------------------------------
# Test orchestration (unchanged)
# -----------------------------------------------------------------------------

@app.route("/start_test", methods=["POST"])
def start_test():
    tid = test_tracker.start_test()
    return jsonify({"test_id": tid})


@app.route("/end_test", methods=["POST"])
def end_test():
    out = test_tracker.end_test()
    return jsonify({"results": out})

# -----------------------------------------------------------------------------
# Entry‑point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print(colored("Starting Auth Demo on http://127.0.0.1:5000", "green"))
    app.run(debug=True)
