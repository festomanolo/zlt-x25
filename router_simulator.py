#!/usr/bin/env python3
"""
router_simulator.py — a fake "router" for testing zlt_dumper.py locally.

This is a self-contained sandbox target. It binds ONLY to 127.0.0.1 (never
reachable from your LAN or anyone else's device) and pretends to be a
BusyBox-based router shell with a login prompt, a handful of synthetic
flash (MTD) partitions, and a couple of synthetic UBI volumes, so you can
exercise zlt_dumper.py's actual logic end to end without ever touching
real hardware: credential guessing against a real login/password
challenge, partition + UBI-volume parsing, the RAM-safe HTTP download
path, the direct TCP streaming path, and MD5 verification.

It is NOT a copy of any real router's firmware or behavior beyond the
handful of shell commands zlt_dumper.py happens to run; it just answers
those specific commands with made-up, clearly-labeled synthetic data.

Usage:
    sudo python3 router_simulator.py

(sudo is only needed because the simulated "web login page" binds to port
80, which is a privileged port on macOS/Linux regardless of the fact that
it's loopback-only. Everything else uses high, unprivileged ports.)

Then, when running zlt_dumper.py, enter "127.0.0.1" as the router IP at
Step 1, and at Step 2 just press Enter (no sessionId needed) -- the
simulator's fake shell port is already listening and gets picked up by
zlt_dumper.py's "existing shell" check before any injection step ever
runs. It will then genuinely walk through its default credential list
against the fixture's login prompt (several will be rejected with "Login
incorrect" before one succeeds), so the credential-handling code path
actually runs, not just a no-op handshake.
"""

import argparse
import hashlib
import http.server
import json
import re
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

HOST = "127.0.0.1"  # loopback only -- never exposed to a real network
WEB_PORT = 80
SHELL_PORT = 4444

# ------------------------------------------------------------------------
# Selectable fault-injection modes. Each one targets a specific failure
# path in zlt_dumper.py so its error-reporting/retry logic can actually be
# exercised against something other than the happy path.
#
#   normal              -- everything works (the default)
#   no-shell            -- no shell service is listening at all
#   all-creds-fail      -- every entry in default_creds is rejected
#   no-httpd            -- "busybox httpd" never actually starts a server,
#                           forcing every partition through the direct
#                           TCP-stream fallback path instead
#   corrupt-partition   -- one partition's reported MD5 is deliberately
#                           wrong, to trigger the mismatch/retry/FAILED path
#   slow-shell          -- every post-login command reply is delayed, to
#                           exercise timeout handling under latency
# ------------------------------------------------------------------------
MODES = ["normal", "no-shell", "all-creds-fail", "no-httpd", "corrupt-partition", "slow-shell"]
MODE = "normal"

CORRUPT_TARGET = "misc"  # partition name used by corrupt-partition mode
SLOW_DELAY = 4.0  # seconds, used by slow-shell mode

# Fake login credentials the fixture actually enforces, so the dumper's
# credential-guessing loop (RouterShellClient.connect) is genuinely
# exercised against several wrong guesses before it succeeds -- instead of
# just handing over a shell immediately. This intentionally does NOT match
# the first entry in zlt_dumper.py's default_creds list, so "root"/"admin"
# is tried and rejected before "admin"/"admin" succeeds.
VALID_USER = "admin"
VALID_PASS = "admin"

# Synthetic flash layout loosely modeled on a Unisoc-based LTE CPE's usual
# partition names (splloader/uboot/boot/recovery/misc/rootfs/userdata plus
# a UBI-backed data volume). Sizes are kept small so the demo runs in
# seconds; this is NOT an extracted or reverse-engineered copy of any real
# ZLT X25 firmware layout -- it's made-up, clearly-labeled test data that
# just needs to look and behave like a plausible flash map so the dumper's
# parsing/extraction code gets exercised realistically.
MTD_PARTITIONS = [
    # (name, size_bytes)
    ("splloader", 128 * 1024),
    ("uboot", 512 * 1024),
    ("boot", 4 * 1024 * 1024),
    ("recovery", 4 * 1024 * 1024),
    ("misc", 512 * 1024),
    ("fw_env", 128 * 1024),
    ("rootfs", 8 * 1024 * 1024),
    ("ubi", 12 * 1024 * 1024),  # backs the synthetic UBI volumes below
]

# Synthetic UBI volumes living on the "ubi" MTD partition above, matching
# the pipe-delimited format zlt_dumper.py's UBI-discovery one-liner expects:
# "<ubi dev>|<usable_eb_size>|<data_bytes>|<name>"
UBI_VOLUMES = [
    # (ubi_dev, usable_eb_size, data_bytes, name)
    ("ubi0_0", 126976, 3 * 1024 * 1024, "userdata"),
    ("ubi0_1", 126976, 1 * 1024 * 1024, "nvram"),
]
UBI_BYTES = {name: None for _, _, _, name in UBI_VOLUMES}  # filled in below

WORKDIR = Path(tempfile.mkdtemp(prefix="zlt_sim_"))
print(f"[sim] scratch /tmp for the fake router lives at: {WORKDIR}")


def device_bytes(name: str, size: int) -> bytes:
    """Deterministic pseudo-random content for a given virtual device, so
    repeated reads (dd, md5sum, HTTP GET, TCP stream) always agree."""
    out = bytearray()
    counter = 0
    seed = f"ZLT-SIM:{name}".encode("utf-8")
    while len(out) < size:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:size])


PARTITION_BYTES = {name: device_bytes(name, size) for name, size in MTD_PARTITIONS}
PARTITION_SIZE = {name: size for name, size in MTD_PARTITIONS}
UBI_BYTES = {
    name: device_bytes(f"ubi:{name}", size) for _, _, size, name in UBI_VOLUMES
}
UBI_SIZE = {name: size for _, _, size, name in UBI_VOLUMES}
UBI_DEV_BY_NAME = {name: dev for dev, _, _, name in UBI_VOLUMES}

_httpd_thread = None
_httpd_server = None


def start_fake_busybox_httpd(port: int) -> None:
    """Starts serving WORKDIR over HTTP, mimicking `busybox httpd -h /tmp`."""
    global _httpd_thread, _httpd_server
    if _httpd_server is not None:
        return

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

    handler = lambda *a, **kw: QuietHandler(*a, directory=str(WORKDIR), **kw)
    _httpd_server = http.server.ThreadingHTTPServer((HOST, port), handler)
    _httpd_thread = threading.Thread(target=_httpd_server.serve_forever, daemon=True)
    _httpd_thread.start()
    print(f"[sim] fake busybox httpd serving {WORKDIR} on http://{HOST}:{port}/")


# ------------------------------------------------------------------------
# Fake shell command dispatcher -- only understands the exact handful of
# commands zlt_dumper.py sends, nothing more.
# ------------------------------------------------------------------------

def run_inner_cmd(cmd: str) -> str:
    cmd = cmd.strip()

    m = re.match(r"^echo ([A-Za-z0-9_]+)$", cmd)
    if m:
        return m.group(1)

    if cmd == "uname -a":
        return (
            "Linux zlt-sim 4.4.0-sim #1 SMP PREEMPT (simulated) "
            "armv7l GNU/Linux  [ZLT-SIM test fixture -- not a real device]"
        )

    if cmd == "df -h /tmp | tail -n 1":
        return "tmpfs            64.0M     12.0M     52.0M  19% /tmp"

    if cmd == "df -k /tmp | tail -n 1":
        # Needs >= 3 numeric fields: blocks, used, available
        return "tmpfs             65536      12288      53248  19% /tmp"

    if cmd == "cat /proc/mtd":
        lines = ['dev:    size   erasesize  name']
        for i, (name, size) in enumerate(MTD_PARTITIONS):
            lines.append(f'mtd{i}: {size:08x} 00010000 "{name}"')
        return "\n".join(lines)

    if "/sys/class/ubi/ubi0_" in cmd:
        # The discovery one-liner, not a dd/md5sum command that merely
        # mentions a /dev/ubi0_N path.
        lines = [
            f"{dev}|{eb_size}|{data_bytes}|{name}"
            for dev, eb_size, data_bytes, name in UBI_VOLUMES
        ]
        return "\n".join(lines)

    m = re.match(r"^rm -f (.+)$", cmd)
    if m:
        for pattern in m.group(1).split():
            for f in WORKDIR.glob(Path(pattern).name):
                try:
                    f.unlink()
                except OSError:
                    pass
        return ""

    if re.match(r"^busybox httpd -p \d+ -h /tmp \|\| httpd -p \d+ -h /tmp$", cmd):
        if MODE == "no-httpd":
            # Pretend the command ran but no daemon actually came up, so the
            # dumper's own HTTP probe (fetching zlt_probe.txt) fails and it
            # falls back to the direct TCP-stream path for every partition.
            return ""
        port = int(re.search(r"-p (\d+)", cmd).group(1))
        start_fake_busybox_httpd(port)
        return ""

    m = re.match(r"^echo (\S+) > (/tmp/\S+)$", cmd)
    if m:
        (WORKDIR / Path(m.group(2)).name).write_text(m.group(1) + "\n")
        return ""

    m = re.match(r"^dd if=/dev/(mtd\d+|ubi\d+_\d+) of=(/tmp/\S+) bs=4096$", cmd)
    if m:
        name, size, data = _resolve_device(m.group(1))
        if data is None:
            return f"dd: /dev/{m.group(1)}: No such device"
        (WORKDIR / Path(m.group(2)).name).write_bytes(data)
        blocks = -(-size // 4096)
        return f"{blocks}+0 records in\n{blocks}+0 records out\n{size} bytes copied"

    m = re.match(r"^md5sum (/tmp/\S+|/dev/(?:mtd\d+|ubi\d+_\d+))$", cmd)
    if m:
        target = m.group(1)
        if target.startswith("/dev/"):
            name, _, data = _resolve_device(target[len("/dev/"):])
            data = data or b""
        else:
            fname = Path(target).name
            idm = re.match(r"^zlt_dump_(.+)\.bin$", fname)
            name, _, _ = _resolve_device(idm.group(1)) if idm else (None, 0, None)
            path = WORKDIR / fname
            data = path.read_bytes() if path.exists() else b""

        if MODE == "corrupt-partition" and name == CORRUPT_TARGET:
            # Deliberately wrong checksum -- as if the router's own
            # md5sum (or the flash read itself) is unreliable for this
            # partition. The bytes actually served over HTTP/TCP stay
            # correct, so the dumper's own locally-computed MD5 will
            # legitimately disagree with this and should report FAILED.
            return f"{'0' * 32}  {target}"

        return f"{hashlib.md5(data).hexdigest()}  {target}"

    m = re.match(
        r"^dd if=/dev/(mtd\d+|ubi\d+_\d+) bs=4096 2>/dev/null \| nc (\S+) (\d+) \|\| .*$",
        cmd,
    )
    if m:
        name, _, data = _resolve_device(m.group(1))
        target_ip, target_port = m.group(2), int(m.group(3))
        if data is None:
            return f"dd: /dev/{m.group(1)}: No such device"
        try:
            with socket.create_connection((target_ip, target_port), timeout=10) as s:
                s.sendall(data)
        except OSError as exc:
            return f"[sim] stream to {target_ip}:{target_port} failed: {exc}"
        return ""

    return f"[sim] (unrecognized command, ignored): {cmd}"


def _resolve_device(dev_id: str):
    """Maps a bare device id (e.g. "mtd4" or "ubi0_1") to (name, size, bytes),
    or (dev_id, 0, None) if it isn't one of our synthetic devices."""
    m = re.match(r"^mtd(\d+)$", dev_id)
    if m:
        idx = int(m.group(1))
        if idx < len(MTD_PARTITIONS):
            name, size = MTD_PARTITIONS[idx]
            return name, size, PARTITION_BYTES[name]
        return dev_id, 0, None

    for dev, _, size, name in UBI_VOLUMES:
        if dev == dev_id:
            return name, size, UBI_BYTES[name]
    return dev_id, 0, None


COMMAND_RE = re.compile(r"^echo (\S+)_START; (.*); echo \1_END:\$\?$")

LOGIN_BANNER = (
    b"BusyBox v1.33.1 (simulated) built-in shell (ash)\r\n"
    b"[ZLT-SIM router] this is a local test fixture, not a real device\r\n"
    b"zlt-sim login: "
)
SHELL_PROMPT = b"\r\nWelcome.\r\n/ # "
LOGIN_RETRY = b"\r\nLogin incorrect\r\nzlt-sim login: "


def handle_connection(conn: socket.socket) -> None:
    """Runs a tiny login state machine (WAIT_USER -> WAIT_PASS -> shell) so
    zlt_dumper.py's credential-guessing loop gets genuinely exercised: wrong
    guesses are rejected with "Login incorrect" and a fresh "login:" prompt,
    exactly like real BusyBox telnetd, until a valid pair is sent."""
    try:
        conn.sendall(LOGIN_BANNER)
        state = "WAIT_USER"
        pending_user = ""
        authenticated = False
        buf = b""
        conn.settimeout(300)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buf += data
            while b"\n" in buf:
                raw_line, buf = buf.split(b"\n", 1)
                line = raw_line.decode("utf-8", errors="ignore").strip("\r").strip()

                if not authenticated:
                    if state == "WAIT_USER":
                        if not line:
                            continue
                        pending_user = line
                        state = "WAIT_PASS"
                        conn.sendall(b"Password: ")
                    elif state == "WAIT_PASS":
                        pwd = line
                        creds_ok = (
                            pending_user == VALID_USER
                            and pwd == VALID_PASS
                            and MODE != "all-creds-fail"
                        )
                        if creds_ok:
                            authenticated = True
                            conn.sendall(SHELL_PROMPT)
                        else:
                            conn.sendall(LOGIN_RETRY)
                            state = "WAIT_USER"
                    continue

                if not line:
                    continue
                m = COMMAND_RE.match(line)
                if not m:
                    continue  # ignore anything that isn't the expected wrapper
                token, inner = m.group(1), m.group(2)
                if MODE == "slow-shell":
                    time.sleep(SLOW_DELAY)
                output = run_inner_cmd(inner)
                reply = f"{token}_START\n{output}\n{token}_END:0\n"
                conn.sendall(reply.encode("utf-8"))
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_fake_shell(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(5)
    print(f"[sim] fake root shell listening on {HOST}:{port}")
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_connection, args=(conn,), daemon=True).start()


class FakeWebHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        body = b"<html><body>ZLT-SIM fake router web UI (test fixture)</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # Minimal stand-in for /cgi-bin/http.cgi, in case something posts to
        # it. The fake shell is already listening directly, so the dumper's
        # "existing shell" check succeeds before this would ever be used.
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length)
        body = json.dumps({"result": "ok", "note": "ZLT-SIM fixture"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve_fake_web(port: int) -> None:
    try:
        srv = http.server.ThreadingHTTPServer((HOST, port), FakeWebHandler)
    except PermissionError:
        print(
            f"[sim] ERROR: permission denied binding {HOST}:{port}.\n"
            f"       Ports below 1024 need elevated privileges even on loopback.\n"
            f"       Re-run as: sudo python3 {Path(__file__).name}"
        )
        sys.exit(1)
    print(f"[sim] fake web login page on http://{HOST}:{port}/")
    srv.serve_forever()


def main() -> None:
    global MODE

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--mode",
        choices=MODES,
        default="normal",
        help="fault-injection mode to simulate (default: normal)",
    )
    args = ap.parse_args()
    MODE = args.mode

    print("=" * 70)
    print(" ZLT-SIM -- local test fixture for zlt_dumper.py")
    print(f" Mode: {MODE}")
    print(" Binds ONLY to 127.0.0.1. Point zlt_dumper.py at router IP 127.0.0.1")
    print(" and skip the sessionId prompt (press Enter) -- the fake shell is")
    print(" already up, so the dumper finds it via its normal port probe.")
    print("=" * 70)

    if MODE == "no-shell":
        print("[sim] mode=no-shell: the shell port is intentionally NOT started")
    else:
        shell_thread = threading.Thread(
            target=serve_fake_shell, args=(SHELL_PORT,), daemon=True
        )
        shell_thread.start()
    time.sleep(0.2)

    try:
        serve_fake_web(WEB_PORT)
    except KeyboardInterrupt:
        print("\n[sim] shutting down.")


if __name__ == "__main__":
    main()
