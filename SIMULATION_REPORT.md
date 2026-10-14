# zlt_dumper.py — Local Simulation & Failure-Mode Report

**Date:** 2026-10-14
**Scope:** `zlt_dumper.py` (firmware partition dumper CLI) tested against `router_simulator.py` (a local, loopback-only fake router fixture). No real router, real credentials, or real network was involved in any test described here — everything ran against `127.0.0.1`.

---

## 1. Purpose

`zlt_dumper.py` is an interactive CLI that connects to a router's shell (by finding an already-open Telnet-like port, or via credential guessing against a login prompt), discovers flash partitions (`/proc/mtd`, UBI volumes), and dumps them to the local Mac over either an HTTP download or a direct TCP stream, verifying each with MD5.

The goal of this exercise was to answer two questions without touching real hardware:

1. **Does the dumper's own logic work correctly** when given a well-behaved target? (regression baseline)
2. **How does it behave, and how clear are its error messages, when the target misbehaves** in ways a real device plausibly would — wrong credentials, a missing service, a lying checksum, a slow shell?

To do this, `router_simulator.py` was built as a self-contained test double: it binds only to `127.0.0.1`, presents a BusyBox-like login and shell, and answers the exact handful of shell commands the dumper sends with synthetic, clearly-labeled data (not an extracted or reverse-engineered copy of any real firmware).

---

## 2. Simulator architecture (`router_simulator.py`)

| Component | Behavior |
|---|---|
| Fake "web UI" (port 80, needs `sudo` to bind) | Returns 200 OK on `GET /`, so Step 1's reachability check passes. Minimal `/cgi-bin/http.cgi` stub exists but is never exercised, because the fake shell is already listening directly — the dumper's "existing shell" check finds it before any injection step would run. |
| Fake shell (port 4444) | A small state machine: `WAIT_USER → WAIT_PASS → authenticated shell`. Requires a real username/password exchange (`admin`/`admin`), rejecting wrong guesses with `"Login incorrect"` and a fresh prompt — exactly like real BusyBox telnetd — so the dumper's actual credential-guessing loop runs for real, not as a no-op. |
| Synthetic flash layout | 8 MTD partitions + 2 UBI volumes, loosely shaped like a typical Unisoc-based LTE CPE flash map (`splloader`, `uboot`, `boot`, `recovery`, `misc`, `fw_env`, `rootfs`, `ubi` + `userdata`/`nvram` UBI volumes). Content is deterministic pseudo-random bytes (SHA-256 counter-mode), so repeated reads (`dd`, `md5sum`, HTTP GET, TCP stream) always agree unless a fault mode deliberately makes them disagree. |
| Command dispatcher | Recognizes only the exact commands `zlt_dumper.py` sends (`cat /proc/mtd`, the UBI discovery one-liner, `dd if=... of=... bs=4096`, `md5sum ...`, `busybox httpd ...`, the `dd | nc` streaming pipeline, etc.) and answers each with synthetic but structurally correct output. |
| Fault-injection modes | `--mode=<name>` flag (see §4) that make specific commands misbehave, to exercise the dumper's error paths on purpose. |

---

## 3. Baseline regression (`--mode=normal`)

Ran the real `zlt_dumper.py` code (not a reimplementation — the actual `RouterShellClient`, `step_4_discover_partitions`, `step_5_dump_partitions`, etc.) against the simulator twice, before and after the fixes in §5, to confirm no regression.

**Result: 10/10 partitions discovered, downloaded, and MD5-verified correctly, both times.**

```
✔ VERIFIED  mtd0_splloader.bin   128.0 KB
✔ VERIFIED  mtd1_uboot.bin       512.0 KB
✔ VERIFIED  mtd2_boot.bin          4.00 MB
✔ VERIFIED  mtd3_recovery.bin      4.00 MB
✔ VERIFIED  mtd4_misc.bin        512.0 KB
✔ VERIFIED  mtd5_fw_env.bin      128.0 KB
✔ VERIFIED  mtd6_rootfs.bin        8.00 MB
✔ VERIFIED  mtd7_ubi.bin          12.00 MB
✔ VERIFIED  ubi0_0_userdata.bin    3.00 MB
✔ VERIFIED  ubi0_1_nvram.bin       1.00 MB
```

This confirms the dumper's core logic — partition parsing, the RAM-safe HTTP path, and MD5 verification — is sound against a well-behaved target.

---

## 4. Fault-injection modes: results

Each mode isolates one plausible real-world failure cause. All were run against the actual dumper code via a scripted harness (not manual reasoning about what "should" happen).

### 4.1 `no-shell` — nothing listening on any shell port

**Simulates:** the device has no Telnet/shell service reachable at all (firewalled, `telnetd` not present, wrong port).

**Before the earlier session's fixes**, this would have returned a bare `False` with no explanation.

**Result after fixes:**
```
connect() ok: False
last_error : connect to 127.0.0.1:4444 failed: connection refused (nothing listening on that port)
```
Correct, specific, actionable.

### 4.2 `all-creds-fail` — login prompt rejects every credential

**Simulates:** the device is reachable and has a real login prompt, but none of the dumper's built-in default credentials apply (changed password, different firmware build, etc.) — very plausibly the actual cause if a friend's device "isn't working."

**Result found a real reporting gap, then fixed it:**

- **Before fix:** `last_error` showed only the first 120 characters of the *initial banner* — it didn't say credentials were even tried, let alone how many or which ones. Someone debugging this would have no idea whether the connection, the login flow, or something else failed.
- **After fix:** `last_error` now reads:
  ```
  login prompt on 127.0.0.1:4444 rejected all 4 credential(s) tried: ['root', 'admin', 'Gztz@83583#', 'telecomadmin']
  ```
  This tells you exactly what was attempted and that all of it was rejected — the single most likely real-world explanation for "my friend's dumper isn't working."

### 4.3 `no-httpd` — `busybox httpd` never actually starts

**Simulates:** a BusyBox build without the `httpd` applet, or one where it silently fails to bind.

**Result:** the dumper's own HTTP probe (fetching a known file right after trying to start the server) correctly detected the failure (`httpd_active: False`) and fell back to "Direct TCP Socket Streaming" for **every** partition, not just the large ones. Both partitions tested in this run downloaded and verified correctly over the TCP-stream path. No changes needed here — this fallback already worked correctly.

### 4.4 `corrupt-partition` — router reports a wrong checksum for one partition

**Simulates:** flaky flash, a read error, or an unreliable `md5sum` on one partition specifically (the `misc` partition was the designated target; all bytes actually served over HTTP stayed correct — only the *reported* checksum was deliberately wrong).

**Result:**
```
(5/10) Processing /dev/mtd4 (misc • 512.0 KB)
  ↻ Retrying /dev/mtd4 (Attempt 2/2)...
  ✘ Failed to dump /dev/mtd4: MD5 mismatch (Router: 00000...000 vs Mac: 38eb9bde...)
...
│ /dev/mtd4   │ mtd4_misc.bin │ 512.0 KB │ - │ ✘ FAILED │
```
The other 9 partitions still verified correctly. The retry-then-fail logic, and the summary table correctly isolating one bad partition from an otherwise successful run, both worked exactly as designed. No changes needed.

### 4.5 `slow-shell` — every post-login command is delayed 4 seconds

**Simulates:** a loaded/slow device, or one with laggy Telnet.

**Result:** login succeeded (delay only applies after authentication in this mode), but the subsequent readiness check (`echo ZLT_READY_CHECK`, 4-second internal timeout) narrowly failed against the 4-second delay, producing:
```
connect() ok: False
last_error : got what looked like a shell prompt ..., but command execution did not echo back correctly (got: '')
```
This is a reasonable, specific failure message — no crash, no hang, no silent wrong answer. This test is also what surfaced the unrelated bug described in §5.2.

---

## 5. Bugs found in `zlt_dumper.py` itself, and fixes applied

These were found by actually running the real code against the fixture, not by inspection alone.

### 5.1 Weak shell-prompt detection → false positives/negatives

**Before:** `RouterShellClient.connect()` decided a shell prompt was present if the response merely *contained* `#`, `$`, or `/` anywhere — any MOTD, error banner, or path mentioned in a login-failure message could trigger a false positive, and a legitimate prompt ending in a different symbol would be missed.

**Fix:** replaced with an end-of-line regex (`[#$%>]\s*$`) that only matches a line actually ending in a shell-prompt character, matched per-line against the full response.

### 5.2 `_read_raw()` could silently take up to ~2x its stated timeout

**Found via the `slow-shell` test**, though it turned out to be independent of that mode specifically — a latent issue in the original code.

**Before:**
```python
self.sock.settimeout(timeout)        # set ONCE
while time.time() - start < timeout:
    raw = self.sock.recv(4096)       # each recv() can still block up to `timeout`
    ...
```
Because `settimeout()` sets a **per-call** blocking limit, not a deadline, a `recv()` that happens late in the loop (e.g. right after a chunk of data already arrived) could itself block for nearly the *full* `timeout` again before raising `socket.timeout` — even though the outer loop's intent was to bound the *total* wait to `timeout`.

**Fix:**
```python
while True:
    remaining = timeout - (time.time() - start)
    if remaining <= 0:
        break
    self.sock.settimeout(remaining)  # shrinks each call to what's actually left
    raw = self.sock.recv(4096)
    ...
```
Now each `recv()` only gets what's actually left of the stated budget, so `_read_raw(timeout=2.0)` can no longer overshoot to ~4s in the worst case.

**Important caveat, found while testing this fix:** this was **not** the reason login against the simulator takes ~12–17 seconds. That duration is intentional by design — `connect()` deliberately waits close to the full ~2-second window after each login exchange to make sure a multi-packet response has fully arrived before deciding the shell is ready. The fix is still correct and worth keeping (it removes a genuine worst-case overshoot), but it is a minor tightening, not the explanation for the overall login latency. Documenting this explicitly so it isn't mischaracterized later as "fixed the slow login" — it didn't; the login is slow by design, and that's a separate, deliberate trade-off (favoring reliability over speed against a flaky Telnet session) that nothing here changed.

### 5.3 (From the previous session, included for completeness) Error visibility

Before any of this, nearly every network call (`connect()`, `check_http_cgi()`, `send_cgi_payload()`) swallowed its exception with a bare `except Exception: return False`, discarding the actual cause. All of these now:
- Log full tracebacks to `~/Downloads/zlt_dumper_debug.log` (stderr too, if `ZLT_DEBUG=1` is set)
- Report a specific, human-readable reason via `describe_exception()` (timeout vs. connection refused vs. DNS failure vs. TLS error vs. other `OSError`) instead of a generic string or nothing at all
- Populate a new `RouterShellClient.last_error` field so callers can report *why*, not just *that*, a connection attempt failed

---

## 6. Why the dumper most likely "wasn't working" for your friend

Tying the fault-injection results back to the original question — none of this was testable against the real device, but the simulator results narrow down the plausible causes, in order of likelihood based on how each mode's symptoms map to "clean code, doesn't work":

1. **Most likely: credentials don't match (§4.2).** The default credential list is a fixed guess; if the device's password was ever changed by the carrier or the owner, the dumper will exhaust every guess and fail — and, before this session's fix, would have given almost no indication of why.
2. **Also plausible: firmware patched the CGI injection endpoint**, or `telnetd` isn't present in that BusyBox build at all — equivalent to `no-shell` (§4.1): nothing is ever listening, no matter what credentials are tried. This is unverifiable without touching the real device, which is out of scope here.
3. **Less likely but possible: `busybox httpd` unavailable (§4.3)** — would only cause a fallback to the slower TCP-stream path, not an outright failure, so probably not the root cause of a complete non-functional report.
4. **Unlikely to be the root "doesn't work" cause, but worth knowing about: a slow or loaded device (§4.5)** could cause the initial readiness check to fail even after a seemingly successful login, producing a confusing "it connected but then nothing happened" symptom.

Given the code itself is structurally sound (confirmed by the clean 10/10 baseline run), the most defensible explanation for "it's not working" on your friend's unit remains a **mismatch between the script's hardcoded assumptions (credentials, firmware CGI behavior, or BusyBox applets present) and that specific device's actual state** — not a bug in the dumper's extraction/verification logic, which tested out correctly in every scenario where a shell was actually reachable.

---

## 7. How to reproduce any of this

```bash
cd /Volumes/macx/projects/zlt-x25

# Interactive, normal mode:
sudo python3 router_simulator.py --mode=normal
python3 zlt_dumper.py     # enter 127.0.0.1, press Enter past sessionId

# Any fault mode:
sudo python3 router_simulator.py --mode=all-creds-fail
# modes: normal | no-shell | all-creds-fail | no-httpd | corrupt-partition | slow-shell
```

All testing in this report was done via a scripted Python harness driving the real `zlt_dumper.py` classes directly (bypassing only the interactive `Prompt.ask()` calls and the privileged port-80 bind, which this sandboxed environment couldn't satisfy) — not by re-implementing or guessing at its behavior.
