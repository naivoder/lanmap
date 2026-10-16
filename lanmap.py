#!/usr/bin/env python3
"""
lanmap - map the local network from the command line and render an HTML report.

Discovers hosts on the subnets this machine is attached to (ICMP sweep + ARP
neighbour table, arp-scan when available), resolves names (DNS, NetBIOS,
SNMP sysDescr), scans TCP ports with light banner grabbing, records live
connections and (as root) passively captures traffic to map who talks to whom.
The result is a self-contained HTML report with a topology block diagram, an
address map, a flow diagram and a suggested VLAN/zone plan with the
cross-zone rules your observed traffic would need.

Only scan networks you own or are authorised to assess.
"""
from __future__ import annotations

import argparse
import asyncio
import html
import ipaddress
import json
import math
import os
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import webbrowser
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

try:
    from rich import box
    from rich.columns import Columns
    from rich.console import Console
    from rich.padding import Padding
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
except ImportError:  # pragma: no cover
    sys.exit("lanmap needs the 'rich' package:  pip install rich")

__version__ = "1.0.0"

console = Console(highlight=False)
ACCENT = "#3987e5"

# ───────────────────────────── reference data ──────────────────────────────

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
    69: "tftp", 80: "http", 81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios",
    143: "imap", 161: "snmp", 162: "snmp-trap", 179: "bgp", 389: "ldap", 427: "slp",
    443: "https", 445: "smb", 465: "smtps", 500: "ike", 514: "syslog", 515: "lpd",
    548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    902: "vmware", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn",
    1400: "sonos", 1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
    1900: "ssdp", 2049: "nfs", 2222: "ssh-alt", 2375: "docker", 2376: "docker-tls",
    3000: "http-dev", 3128: "proxy", 3260: "iscsi", 3268: "ldap-gc", 3306: "mysql",
    3389: "rdp", 3478: "stun", 3702: "ws-discovery", 4443: "https-alt", 5000: "http-alt",
    5001: "https-alt", 5060: "sip", 5061: "sips", 5353: "mdns", 5355: "llmnr",
    5357: "wsd", 5432: "postgres", 5601: "kibana", 5900: "vnc", 5985: "winrm",
    5986: "winrm-tls", 6379: "redis", 6443: "k8s-api", 7000: "airplay", 8000: "http-alt",
    8006: "proxmox", 8008: "http-alt", 8009: "cast", 8080: "http-proxy", 8081: "http-alt",
    8088: "http-alt", 8123: "home-assistant", 8291: "winbox", 8443: "https-alt",
    8728: "routeros-api", 8883: "mqtt-tls", 8888: "http-alt", 9000: "http-alt",
    9090: "http-admin", 9100: "jetdirect", 9200: "elasticsearch", 9443: "https-alt",
    10000: "webmin", 10001: "ubnt-discovery", 10443: "https-alt", 11211: "memcached",
    27017: "mongodb", 37777: "dahua", 49152: "upnp", 51820: "wireguard", 62078: "iphone-sync",
}
TOP_TCP = sorted(p for p in SERVICES if p not in (67, 68, 69, 123, 137, 138, 161, 162, 500, 514,
                                                   1900, 3478, 3702, 5353, 5355, 10001, 51820))
HTTP_PORTS = {80, 81, 1400, 3000, 5000, 7000, 8000, 8008, 8080, 8081, 8088, 8123, 8888, 9000, 9090, 10000}
HTTPS_PORTS = {443, 4443, 5001, 5986, 6443, 8006, 8443, 9443, 10443}

# Broadcast/multicast protocols that stop working when devices are split across VLANs
DISCOVERY = {
    67: ("DHCP", "needs a DHCP relay (ip helper-address) on every new VLAN"),
    68: ("DHCP", "needs a DHCP relay (ip helper-address) on every new VLAN"),
    137: ("NetBIOS", "legacy Windows name lookup; use DNS instead"),
    138: ("NetBIOS", "legacy Windows browsing; use DNS instead"),
    1900: ("SSDP / UPnP", "casting and media discovery; needs an SSDP proxy across VLANs"),
    3702: ("WS-Discovery", "Windows printer/scanner discovery; add devices by IP"),
    5353: ("mDNS / Bonjour", "AirPrint, AirPlay, Chromecast, Sonos; needs an mDNS reflector"),
    5355: ("LLMNR", "Windows name fallback; use DNS instead"),
    10001: ("Ubiquiti discovery", "controller adoption; use L3 adoption / set-inform"),
}

# zone key, label, suggested VLAN id, description, (light, dark) colour
ZONES = [
    ("infrastructure", "Infrastructure", 10, "Routers, switches, access points, management interfaces", ("#2a78d6", "#3987e5")),
    ("servers", "Servers & storage", 20, "Hypervisors, NAS, directory, database and application servers", ("#eb6834", "#d95926")),
    ("users", "Workstations", 30, "Desktops, laptops and phones", ("#1baf7a", "#199e70")),
    ("printers", "Printers", 40, "Printers, scanners and multifunction devices", ("#eda100", "#c98500")),
    ("voice", "Voice", 50, "IP phones and SIP devices", ("#e87ba4", "#d55181")),
    ("iot", "IoT", 60, "Smart devices, media players, building systems", ("#008300", "#008300")),
    ("cameras", "Cameras", 70, "IP cameras and NVRs", ("#6250d6", "#9085e9")),
    ("unassigned", "Unclassified", None, "Could not be identified; needs a human decision", ("#898781", "#898781")),
]
ZONE = {z[0]: z for z in ZONES}
ZONE_ORDER = {z[0]: i for i, z in enumerate(ZONES)}
PSEUDO_ZONES = {"internet": "Internet", "multicast": "Multicast / broadcast"}

# role -> (badge, label, zone)
ROLES = {
    "gateway": ("GW", "Gateway / router", "infrastructure"),
    "network": ("NET", "Switch / AP", "infrastructure"),
    "server": ("SRV", "Server", "servers"),
    "nas": ("NAS", "Storage", "servers"),
    "client": ("PC", "Workstation", "users"),
    "mobile": ("MOB", "Phone / tablet", "users"),
    "printer": ("PRN", "Printer", "printers"),
    "voip": ("TEL", "VoIP phone", "voice"),
    "iot": ("IOT", "IoT device", "iot"),
    "camera": ("CAM", "Camera / NVR", "cameras"),
    "unknown": ("?", "Unclassified", "unassigned"),
}

# Small fallback OUI table; the full IEEE registry is read from nmap/arp-scan/ieee-data when installed.
BUILTIN_OUI = {
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi", "2CCF67": "Raspberry Pi",
    "005056": "VMware", "000C29": "VMware", "000569": "VMware", "525400": "QEMU/KVM virtual NIC",
    "080027": "VirtualBox", "00155D": "Microsoft Hyper-V", "001132": "Synology", "245EBE": "QNAP",
    "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti", "F09FC2": "Ubiquiti", "788A20": "Ubiquiti",
    "FCECDA": "Ubiquiti", "802AA8": "Ubiquiti", "0418D6": "Ubiquiti", "4419B6": "Hikvision",
    "C056E3": "Hikvision", "240AC4": "Espressif", "30AEA4": "Espressif", "A4CF12": "Espressif",
    "84F3EB": "Espressif", "CC50E3": "Espressif", "BCDDC2": "Espressif", "24620A": "Espressif",
    "000E58": "Sonos", "5CAAFD": "Sonos", "949F3E": "Sonos", "B8E937": "Sonos", "0004F2": "Polycom",
    "805EC0": "Yealink", "001565": "Yealink", "008077": "Brother", "001BA9": "Brother",
}
OUI_PATHS = [
    "/usr/share/nmap/nmap-mac-prefixes", "/usr/share/arp-scan/ieee-oui.txt",
    "/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt", "/usr/share/misc/oui.txt",
]

VIRTUAL_IFACES = ("lo", "docker", "br-", "veth", "virbr", "vmnet", "tun", "tap", "wg", "tailscale",
                  "zt", "cni", "flannel", "cali", "kube", "lxc", "vnet")

# ─────────────────────────────── data model ────────────────────────────────


@dataclass
class Port:
    port: int
    proto: str = "tcp"
    service: str = ""
    banner: str = ""


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    netbios: str = ""
    snmp: str = ""
    ttl: int | None = None
    rtt_ms: float | None = None
    os_guess: str = ""
    role: str = "unknown"
    zone: str = "unassigned"
    subnet: str = ""
    is_gateway: bool = False
    is_self: bool = False
    random_mac: bool = False
    seen_by: list = field(default_factory=list)
    ports: list = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.hostname or self.netbios or ""

    def saw(self, how: str):
        if how not in self.seen_by:
            self.seen_by.append(how)


@dataclass
class Flow:
    src: str
    dst: str
    dport: int
    proto: str
    packets: int = 0
    bytes: int = 0
    source: str = "capture"


@dataclass
class Scan:
    version: str = __version__
    started: str = ""
    finished: str = ""
    duration_s: float = 0.0
    scanner: str = ""
    privileged: bool = False
    interfaces: list = field(default_factory=list)
    subnets: list = field(default_factory=list)
    gateway: str = ""
    dns: list = field(default_factory=list)
    route: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    flows: list = field(default_factory=list)
    vlan_tags: dict = field(default_factory=dict)
    capture_s: int = 0
    ports_scanned: int = 0
    notes: list = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, text: str) -> "Scan":
        d = json.loads(text)
        hosts = []
        for h in d.pop("hosts", []):
            ports = [Port(**p) for p in h.pop("ports", [])]
            hosts.append(Host(**h, ports=ports))
        flows = [Flow(**f) for f in d.pop("flows", [])]
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**known, hosts=hosts, flows=flows)


# ──────────────────────────────── helpers ──────────────────────────────────


def run(cmd: list, timeout: float = 15) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def ip_key(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


def clean(data, limit: int = 100) -> str:
    text = data.decode("latin-1", "replace") if isinstance(data, bytes) else data
    text = re.sub(r"[^\x20-\x7e]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_lan(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in RFC1918)


def is_group_addr(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_multicast or ip.endswith(".255") or ip == "255.255.255.255"


def parse_ports(spec: str) -> list:
    if spec == "top":
        return list(TOP_TCP)
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if part == "top":
            ports.update(TOP_TCP)
        elif "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def raise_fd_limit():
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 8192), hard))
    except (ImportError, ValueError, OSError):
        pass


class OUI:
    def __init__(self):
        self.cache = dict(BUILTIN_OUI)
        self.paths = [p for p in OUI_PATHS if os.path.exists(p)]

    def lookup_many(self, macs) -> dict:
        wanted = {m.replace(":", "").upper()[:6] for m in macs if m}
        missing = wanted - set(self.cache)
        rx = re.compile(r"^([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})\s+(?:\(hex\)\s+)?(.+)$")
        for path in self.paths:
            if not missing:
                break
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        m = rx.match(line)
                        if m:
                            key = (m.group(1) + m.group(2) + m.group(3)).upper()
                            if key in missing:
                                self.cache[key] = m.group(4).strip()
                                missing.discard(key)
            except OSError:
                continue
        return {m: self.cache.get(m.replace(":", "").upper()[:6], "") for m in macs if m}


# ─────────────────────────────── terminal UI ───────────────────────────────


class PhaseCtl:
    def __init__(self, progress, task):
        self.progress, self.task, self.summary = progress, task, ""

    def advance(self, n: int = 1):
        if self.progress:
            self.progress.advance(self.task, n)

    def total(self, n: int):
        if self.progress:
            self.progress.update(self.task, total=n)

    def note(self, text: str):
        if self.progress:
            self.progress.update(self.task, note=text)


QUIET = False


@contextmanager
def phase(name: str, total: int | None = None):
    if QUIET:
        yield PhaseCtl(None, None)
        return
    prog = Progress(
        SpinnerColumn("dots", style=ACCENT),
        TextColumn(f"[bold]{name:<11}[/]"),
        BarColumn(bar_width=30, style="grey23", complete_style=ACCENT, finished_style=ACCENT),
        TextColumn("[grey62]{task.completed}/{task.total}" if total else ""),
        TextColumn("[grey50]{task.fields[note]}"),
        TimeElapsedColumn(),
        console=console, transient=True,
    )
    t0 = time.monotonic()
    with prog:
        ctl = PhaseCtl(prog, prog.add_task(name, total=total, note=""))
        yield ctl
    dt = time.monotonic() - t0
    console.print(f"  [{ACCENT}]✓[/] [bold]{name:<11}[/] {ctl.summary}  [grey42]{dt:.1f}s[/]")


def info(msg: str):
    if not QUIET:
        console.print(f"  [grey50]·[/] [grey62]{msg}[/]")


def warn(msg: str):
    console.print(f"  [yellow]![/] {msg}")


# ──────────────────────────────── discovery ────────────────────────────────


def gather_interfaces(include_virtual: bool, only: list | None) -> list:
    raw = run(["ip", "-j", "addr", "show"])
    try:
        links = json.loads(raw or "[]")
    except json.JSONDecodeError:
        links = []
    out = []
    for link in links:
        name, flags = link.get("ifname", ""), link.get("flags", [])
        if "LOOPBACK" in flags or "UP" not in flags:
            continue
        if only and name not in only:
            continue
        if not only and not include_virtual and name.startswith(VIRTUAL_IFACES):
            continue
        for a in link.get("addr_info", []):
            if a.get("family") != "inet" or a.get("prefixlen", 32) >= 31:
                continue
            net = ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network
            out.append({"name": name, "mac": link.get("address", ""), "ip": a["local"],
                        "cidr": str(net), "prefix": a["prefixlen"]})
    return out


def default_gateway() -> tuple:
    try:
        routes = json.loads(run(["ip", "-j", "route", "show", "default"]) or "[]")
    except json.JSONDecodeError:
        routes = []
    for r in routes:
        if r.get("gateway"):
            return r["gateway"], r.get("dev", "")
    return "", ""


def dns_servers() -> list:
    found = []
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                found.append(parts[1])
    except OSError:
        pass
    if not found or all(ip.startswith("127.") for ip in found):
        upstream = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", run(["resolvectl", "dns"], 5))
        found = [ip for ip in upstream if not ip.startswith("127.")] or found
    return list(dict.fromkeys(found))


def traceroute(target: str = "1.1.1.1") -> list:
    if shutil.which("traceroute"):
        out = run(["traceroute", "-n", "-q", "1", "-w", "1", "-m", "8", target], 30)
    elif shutil.which("tracepath"):
        out = run(["tracepath", "-n", "-m", "8", target], 30)
    else:
        return []
    hops = {}
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)\??:?\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
        if m:
            hops.setdefault(int(m.group(1)), m.group(2))
        elif re.match(r"^\s*(\d+)\??:?\s+(\*|no reply)", line):
            n = int(re.match(r"^\s*(\d+)", line).group(1))
            hops.setdefault(n, "")
    return [{"hop": n, "ip": ip} for n, ip in sorted(hops.items())]


async def ping(ip: str, sem: asyncio.Semaphore, timeout: int):
    async with sem:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-n", "-c", "1", "-W", str(timeout), ip,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await proc.communicate()
        except OSError:
            return None
    m_ttl = re.search(rb"ttl=(\d+)", out, re.I)
    if proc.returncode != 0 or not m_ttl:
        return None
    m_t = re.search(rb"time[=<]([\d.]+)", out)
    return int(m_ttl.group(1)), float(m_t.group(1)) if m_t else None


async def tcp_alive(ip: str, sem: asyncio.Semaphore, timeout: float) -> bool:
    async def one(port):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            w.close()
            return True
        except ConnectionRefusedError:
            return True  # an RST still proves the host is there
        except (OSError, asyncio.TimeoutError):
            return False
    async with sem:
        results = await asyncio.gather(*(one(p) for p in (22, 80, 443, 445, 3389, 8080)))
    return any(results)


def neighbours() -> dict:
    try:
        entries = json.loads(run(["ip", "-j", "neigh", "show"]) or "[]")
    except json.JSONDecodeError:
        return {}
    ok = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
    return {e["dst"]: e["lladdr"] for e in entries
            if e.get("lladdr") and ok & set(e.get("state", [])) and ":" not in e.get("dst", ":")}


def arp_scan(iface: str, cidr: str) -> dict:
    out = run(["arp-scan", f"--interface={iface}", "--plain", "--retry=2", cidr], 120)
    found = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            found[parts[0]] = parts[1].lower()
    return found


# ─────────────────────────── names / UDP probes ────────────────────────────

NBSTAT_QUERY = (b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x20" + b"CK" + b"A" * 30 + b"\x00\x00\x21\x00\x01")
SYSDESCR_OID = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
SNMP_GET = (b"\x30\x29\x02\x01\x01\x04\x06public\xa0\x1c\x02\x04\x1a\x2b\x3c\x4d"
            b"\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08" + SYSDESCR_OID + b"\x05\x00")


def parse_nbstat(data: bytes) -> str:
    if len(data) < 57:
        return ""
    count, off = data[56], 57
    for i in range(count):
        ent = data[off + 18 * i: off + 18 * i + 18]
        if len(ent) < 18:
            break
        name = ent[:15].decode("ascii", "ignore").strip()
        flags = struct.unpack(">H", ent[16:18])[0]
        if ent[15] == 0 and not flags & 0x8000 and name:
            return name
    return ""


def parse_snmp(data: bytes) -> str:
    i = data.find(SYSDESCR_OID)
    if i < 0 or len(data) < i + 10 or data[i + 8] != 0x04:
        return ""
    k, ln = i + 10, data[i + 9]
    if ln & 0x80:
        nb = ln & 0x7F
        ln = int.from_bytes(data[k:k + nb], "big")
        k += nb
    return clean(data[k:k + ln], 160)


def udp_sweep(ips: list, port: int, payload: bytes, parse, timeout: float = 2.0) -> dict:
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for ip in ips:
            try:
                s.sendto(payload, (ip, port))
            except OSError:
                pass
            time.sleep(0.002)
        s.settimeout(0.2)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, (addr, _) = s.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            try:
                value = parse(data)
            except Exception:
                value = ""
            if value:
                found[addr] = value
    finally:
        s.close()
    return found


def reverse_dns(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return "" if name == ip else name
    except (OSError, UnicodeError):
        return ""


# ──────────────────────────────── port scan ────────────────────────────────


async def probe(ip: str, port: int, sem: asyncio.Semaphore, timeout: float):
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except (OSError, asyncio.TimeoutError):
            return None
        w.close()
        try:
            await asyncio.wait_for(w.wait_closed(), 1)
        except Exception:
            pass
        return port


def summarise_http(data: bytes) -> str:
    text = data.decode("latin-1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return clean(text)
    hdr = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdr[k.strip().lower()] = v.strip()
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = clean(html.unescape(m.group(1)), 70) if m else ""
    parts = [p for p in (title, clean(hdr.get("server", ""), 50)) if p]
    status = lines[0].split(" ")
    if not parts and len(status) > 1:
        parts.append(f"HTTP {status[1]}")
        if status[1].startswith("3") and hdr.get("location"):
            parts.append("→ " + clean(hdr["location"], 60))
    return " · ".join(parts)[:120]


async def grab_banner(ip: str, port: int, sem: asyncio.Semaphore, timeout: float) -> str:
    tls = port in HTTPS_PORTS
    is_http = tls or port in HTTP_PORTS
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    async with sem:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx), timeout)
        except Exception:
            return ""
        loop = asyncio.get_running_loop()
        buf = b""
        try:
            if is_http:
                w.write((f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: lanmap/{__version__}\r\n"
                         "Accept: text/html\r\nConnection: close\r\n\r\n").encode())
                await w.drain()
            end = loop.time() + timeout
            while len(buf) < 16384:
                left = end - loop.time()
                if left <= 0:
                    break
                try:
                    chunk = await asyncio.wait_for(r.read(16384 - len(buf)), left)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                buf += chunk
                if not is_http:
                    break
        except Exception:
            pass
        finally:
            w.close()
    if not buf:
        return ""
    return summarise_http(buf) if is_http else clean(buf.split(b"\n")[0] if b"SSH-" in buf[:8] else buf)


# ─────────────────────────────── flows ─────────────────────────────────────


def port_rank(p: int) -> tuple:
    return (0 if p in SERVICES or p in DISCOVERY else 1 if p < 1024 else 2 if p < 49152 else 3, p)


def orient(src, sport, dst, dport, proto, servers):
    """Return (client, server, service_port) for one observed packet/socket."""
    if proto not in ("tcp", "udp"):
        return src, dst, 0
    if is_group_addr(dst):
        return src, dst, dport
    if (dst, dport) in servers:
        return src, dst, dport
    if (src, sport) in servers:
        return dst, src, sport
    return (dst, src, sport) if port_rank(sport) < port_rank(dport) else (src, dst, dport)


def socket_flows(self_ips: set) -> list:
    listening = set()
    for line in run(["ss", "-Hltun"]).splitlines():
        toks = line.split()
        for t in toks:
            m = re.match(r"^(?:\[.*\]|[\d.*]+)(?:%\S+)?:(\d+)$", t)
            if m:
                listening.add(int(m.group(1)))
                break
    rows = []
    for line in run(["ss", "-Htunp", "state", "established"]).splitlines():
        toks = line.split()
        if not toks:
            continue
        proto = toks[0] if toks[0] in ("tcp", "udp") else "tcp"
        addrs = [m for t in toks for m in [re.match(r"^(?:::ffff:)?(\d+\.\d+\.\d+\.\d+)(?:%\S+)?:(\d+)$", t)] if m]
        if len(addrs) < 2:
            continue
        lip, lport = addrs[0].group(1), int(addrs[0].group(2))
        pip, pport = addrs[1].group(1), int(addrs[1].group(2))
        if lip.startswith("127.") or pip.startswith("127."):
            continue
        if lport in listening:
            rows.append((pip, lip, lport, proto))
        else:
            rows.append((lip, pip, pport, proto))
    return rows


def sniff(iface: str, seconds: int, tick) -> dict:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((iface, 0))
    try:  # promiscuous: see frames not addressed to us (matters on a mirror/SPAN port)
        mreq = struct.pack("iHH8s", socket.if_nametoindex(iface), 1, 0, b"")
        s.setsockopt(263, 1, mreq)  # SOL_PACKET, PACKET_ADD_MEMBERSHIP
    except OSError:
        pass
    s.settimeout(0.25)
    pkts = defaultdict(lambda: [0, 0])
    arp, ipmac, synack, vlans = {}, {}, set(), Counter()
    end, last = time.monotonic() + seconds, 0.0
    try:
        while True:
            now = time.monotonic()
            if now >= end:
                break
            if now - last >= 0.5:
                tick(int(seconds - (end - now)))
                last = now
            try:
                frame = s.recv(65535)
            except socket.timeout:
                continue
            if len(frame) < 14:
                continue
            eth_src = frame[6:12]
            et, off = struct.unpack("!H", frame[12:14])[0], 14
            if et == 0x8100 and len(frame) >= 18:
                vlans[struct.unpack("!H", frame[14:16])[0] & 0x0FFF] += 1
                et, off = struct.unpack("!H", frame[16:18])[0], 18
            if et == 0x0806 and len(frame) >= off + 28:
                spa = socket.inet_ntoa(frame[off + 14:off + 18])
                if spa != "0.0.0.0":
                    arp[spa] = mac_str(frame[off + 8:off + 14])
                continue
            if et != 0x0800 or len(frame) < off + 20:
                continue
            ihl = (frame[off] & 0x0F) * 4
            total = struct.unpack("!H", frame[off + 2:off + 4])[0]
            proto = frame[off + 9]
            src = socket.inet_ntoa(frame[off + 12:off + 16])
            dst = socket.inet_ntoa(frame[off + 16:off + 20])
            ipmac.setdefault(src, mac_str(eth_src))
            l4, sport, dport = off + ihl, 0, 0
            if proto in (6, 17) and len(frame) >= l4 + 4:
                sport, dport = struct.unpack("!HH", frame[l4:l4 + 4])
                if proto == 6 and len(frame) >= l4 + 14 and frame[l4 + 13] & 0x12 == 0x12:
                    synack.add((src, sport))
            pname = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto, f"ip{proto}")
            rec = pkts[(src, sport, dst, dport, pname)]
            rec[0] += 1
            rec[1] += total
    finally:
        s.close()
    return {"pkts": pkts, "arp": arp, "ipmac": ipmac, "synack": synack, "vlans": vlans}


# ───────────────────────────── classification ──────────────────────────────

KW = {
    "camera": ("hikvision", "dahua", "axis communications", "amcrest", "reolink", "hanwha", "vivotek",
               "unifi protect", "ip camera", "ipcam", "network video", "nvr", "dvr", "uniview"),
    "printer": ("printer", "laserjet", "officejet", "deskjet", "brother", "canon", "epson", "xerox",
                "lexmark", "kyocera", "ricoh", "konica", "jetdirect", "zebra", "sharp mx", "imagerunner"),
    "voip": ("polycom", "yealink", "grandstream", "snom", "mitel", "avaya", "cisco ip phone", "fanvil",
             "poly ", "obihai", "algo"),
    "nas": ("synology", "qnap", "truenas", "freenas", "asustor", "netapp", "diskstation", "readynas",
            "terramaster", "unraid"),
    "network": ("ubiquiti", "unifi", "cisco", "aruba", "juniper", "mikrotik", "routeros", "ruckus",
                "meraki", "fortinet", "fortigate", "procurve", "edgeswitch", "edgerouter", "omada",
                "netgear prosafe", "zyxel", "pfsense", "opnsense", "sophos", "watchguard", "switch",
                "access point"),
    "iot": ("espressif", "tuya", "sonos", "roku", "chromecast", "google", "amazon", "philips", "signify",
            "nest", "ring", "ecobee", "lifx", "shelly", "tasmota", "wemo", "belkin", "samsung smartthings",
            "lg electronics", "vizio", "tp-link kasa", "ezviz", "bose", "denon", "honeywell", "lutron",
            "apple tv", "home assistant"),
    "server": ("proxmox", "vmware", "esxi", "qemu", "kvm", "hyper-v", "virtualbox", "supermicro",
               "idrac", "ilo", "ipmi", "xen", "domain controller", "windows server", "ubuntu", "debian",
               "red hat", "rocky", "almalinux", "centos", "nginx", "apache", "webmin", "cockpit"),
    "mobile": ("iphone", "ipad", "android", "galaxy", "pixel"),
    "client": ("apple", "dell", "lenovo", "intel corporate", "microsoft", "hewlett", "asus", "acer",
               "liteon", "azurewave", "macbook", "desktop-", "laptop"),
}


def classify(h: Host) -> str:
    ports = {p.port for p in h.ports}
    text = " ".join([h.vendor, h.hostname, h.netbios, h.snmp] + [p.banner for p in h.ports]).lower()

    def has(kind):
        return any(k in text for k in KW[kind])

    if h.is_gateway:
        return "gateway"
    if has("camera") or 37777 in ports or (554 in ports and not ports & {445, 22, 5000}):
        return "camera"
    if 9100 in ports or 515 in ports or (has("printer") and ports & {80, 443, 631}):
        return "printer"
    if has("voip") or ports & {5060, 5061} and not ports & {445, 22}:
        return "voip"
    if has("nas") or (2049 in ports and 445 in ports):
        return "nas"
    if has("network") or ports & {8291, 8728} or ("switch" in h.snmp.lower()):
        return "network"
    if ports & {8006, 902, 3306, 5432, 1433, 27017, 6379, 9200, 2375, 6443, 389, 88, 3260, 5985}:
        return "server"
    if has("iot") or ports & {1883, 8883, 8009, 1400}:
        return "iot"
    if 62078 in ports or has("mobile"):
        return "mobile"
    if 3389 in ports or {135, 445} <= ports or 5357 in ports or 7000 in ports or has("client"):
        return "client"
    if has("server") or (22 in ports and ports & {80, 443, 8080}):
        return "server"
    if h.random_mac:
        return "mobile"
    if h.ttl and h.ttl > 128 and ports & {22, 23, 80, 443}:
        return "network"
    return "unknown"


def guess_os(h: Host) -> str:
    ports = {p.port for p in h.ports}
    text = " ".join([h.snmp] + [p.banner for p in h.ports]).lower()
    for key, label in (("routeros", "MikroTik RouterOS"), ("cisco ios", "Cisco IOS"), ("windows", "Windows"),
                       ("ubuntu", "Linux (Ubuntu)"), ("debian", "Linux (Debian)"), ("raspbian", "Linux (Raspberry Pi OS)"),
                       ("freebsd", "FreeBSD"), ("proxmox", "Linux (Proxmox VE)"), ("synology", "Linux (Synology DSM)"),
                       ("openssh", "Unix-like")):
        if key in text:
            return label
    if 3389 in ports or {135, 445} <= ports:
        return "Windows"
    if 62078 in ports:
        return "iOS / iPadOS"
    if h.ttl:
        if h.ttl <= 64:
            return "Linux / Unix / macOS"
        if h.ttl <= 128:
            return "Windows"
        return "Network OS / embedded"
    return ""


def finalise(scan: Scan):
    for h in scan.hosts:
        h.os_guess = h.os_guess or guess_os(h)
        h.role = classify(h)
        h.zone = ROLES[h.role][2]
    scan.hosts.sort(key=lambda h: ip_key(h.ip))


# ─────────────────────────────── the scan ──────────────────────────────────


async def do_scan(opts) -> Scan:
    t0 = time.monotonic()
    scan = Scan(started=datetime.now().isoformat(timespec="seconds"), scanner=socket.gethostname(),
                privileged=is_root())
    raise_fd_limit()
    loop = asyncio.get_running_loop()
    pool = ThreadPoolExecutor(max_workers=48)
    loop.set_default_executor(pool)

    # interfaces & targets
    with phase("Interfaces") as ph:
        ifaces = gather_interfaces(opts.include_virtual, opts.interface)
        gw, gw_dev = default_gateway()
        scan.interfaces, scan.gateway, scan.dns = ifaces, gw, dns_servers()
        targets = [ipaddress.ip_network(t, strict=False) for t in opts.target] if opts.target \
            else [ipaddress.ip_network(i["cidr"]) for i in ifaces]
        targets = list(dict.fromkeys(targets))
        if not targets:
            raise SystemExit("No IPv4 subnets found. Pass one explicitly with --target 192.168.1.0/24")
        for net in targets:
            if not net.is_private and not opts.allow_public:
                raise SystemExit(f"{net} is not a private range. Use --allow-public only for networks you are authorised to scan.")
        size = sum(max(net.num_addresses - 2, 1) for net in targets)
        if size > opts.max_hosts:
            raise SystemExit(f"Targets cover {size:,} addresses (limit {opts.max_hosts:,}). "
                             "Narrow with --target or raise --max-hosts.")
        scan.subnets = [str(n) for n in targets]
        ph.summary = (f"{len(ifaces)} interface{'s' * (len(ifaces) != 1)} · "
                      f"{', '.join(scan.subnets)}" + (f" · gateway {gw}" if gw else ""))

    trace_task = None if opts.no_trace else loop.run_in_executor(None, traceroute)

    hosts: dict = {}

    def host(ip: str) -> Host:
        if ip not in hosts:
            subnet = next((str(n) for n in targets if ipaddress.ip_address(ip) in n), "")
            hosts[ip] = Host(ip=ip, subnet=subnet)
        return hosts[ip]

    on_link = [ipaddress.ip_network(i["cidr"]) for i in ifaces]
    all_ips = [str(ip) for net in targets for ip in (net.hosts() if net.prefixlen < 31 else net)]

    # discovery
    with phase("Discovery", total=len(all_ips)) as ph:
        sem = asyncio.Semaphore(opts.ping_concurrency)

        async def sweep(ip):
            r = await ping(ip, sem, max(1, int(opts.timeout)))
            ph.advance()
            if r:
                h = host(ip)
                h.ttl, h.rtt_ms = r
                h.saw("icmp")

        await asyncio.gather(*(sweep(ip) for ip in all_ips))
        if scan.privileged and shutil.which("arp-scan"):
            ph.note("arp-scan")
            for i in ifaces:
                net = ipaddress.ip_network(i["cidr"])
                if net in targets:
                    for ip, mac in (await loop.run_in_executor(None, arp_scan, i["name"], i["cidr"])).items():
                        h = host(ip)
                        h.mac = h.mac or mac
                        h.saw("arp")
        for ip, mac in neighbours().items():
            if any(ipaddress.ip_address(ip) in n for n in targets):
                h = host(ip)
                h.mac = h.mac or mac.lower()
                h.saw("arp")
        off_link = [ip for ip in all_ips if ip not in hosts
                    and not any(ipaddress.ip_address(ip) in n for n in on_link)]
        if off_link:
            ph.note(f"tcp ping {len(off_link)} routed addresses")
            tsem = asyncio.Semaphore(64)
            alive = await asyncio.gather(*(tcp_alive(ip, tsem, 1.0) for ip in off_link))
            for ip, ok in zip(off_link, alive):
                if ok:
                    host(ip).saw("tcp")
        for i in ifaces:
            if any(ipaddress.ip_address(i["ip"]) in n for n in targets):
                h = host(i["ip"])
                h.is_self, h.mac = True, i["mac"]
                h.saw("self")
        if gw in hosts:
            hosts[gw].is_gateway = True
        ph.summary = f"{len(hosts)} hosts up"

    # identity
    with phase("Identity", total=len(hosts)) as ph:
        oui = OUI()
        vendors = oui.lookup_many([h.mac for h in hosts.values()])
        for h in hosts.values():
            h.vendor = vendors.get(h.mac, "")
            if h.mac and int(h.mac[:2], 16) & 0x02 and not h.vendor:
                h.random_mac = True
                h.vendor = "Private MAC"

        async def name(h):
            try:
                h.hostname = await asyncio.wait_for(loop.run_in_executor(None, reverse_dns, h.ip), 3)
            except asyncio.TimeoutError:
                pass
            ph.advance()

        ips = list(hosts)
        udp = None
        if not opts.no_udp:
            ph.note("netbios / snmp")
            udp = asyncio.gather(loop.run_in_executor(None, udp_sweep, ips, 137, NBSTAT_QUERY, parse_nbstat),
                                 loop.run_in_executor(None, udp_sweep, ips, 161, SNMP_GET, parse_snmp))
        await asyncio.gather(*(name(h) for h in hosts.values()))
        if udp:
            nb, sn = await udp
            for ip, v in nb.items():
                if ip in hosts:
                    hosts[ip].netbios = v
            for ip, v in sn.items():
                if ip in hosts:
                    hosts[ip].snmp = v
        named = sum(1 for h in hosts.values() if h.name)
        ph.summary = (f"{named} named · {sum(1 for h in hosts.values() if h.vendor and not h.random_mac)} vendors"
                      + ("" if oui.paths else " [grey50](install nmap or arp-scan for the full OUI database)[/]"))

    # ports
    ports = parse_ports(opts.ports)
    scan.ports_scanned = len(ports)
    if ports and hosts:
        jobs = [(ip, p) for ip in hosts for p in ports]
        with phase("Ports", total=len(jobs)) as ph:
            sem = asyncio.Semaphore(opts.concurrency)

            async def one(ip, p):
                r = await probe(ip, p, sem, opts.timeout)
                ph.advance()
                return ip, r

            open_ports = [(ip, p) for ip, p in await asyncio.gather(*(one(ip, p) for ip, p in jobs)) if p]
            banners = [""] * len(open_ports)
            if not opts.no_banners and open_ports:
                ph.note(f"banners from {len(open_ports)} services")
                bsem = asyncio.Semaphore(64)
                banners = await asyncio.gather(*(grab_banner(ip, p, bsem, 3.0) for ip, p in open_ports))
            for (ip, p), b in zip(open_ports, banners):
                hosts[ip].ports.append(Port(p, "tcp", SERVICES.get(p, ""), b))
                hosts[ip].saw("tcp")
            for h in hosts.values():
                h.ports.sort(key=lambda x: x.port)
            ph.summary = (f"{len(open_ports)} open across "
                          f"{sum(1 for h in hosts.values() if h.ports)} hosts ({len(ports)} ports each)")
    if opts.no_udp is False:
        for h in hosts.values():
            if h.snmp and not any(p.port == 161 for p in h.ports):
                h.ports.append(Port(161, "udp", "snmp", h.snmp))
            if h.netbios and not any(p.port == 137 for p in h.ports):
                h.ports.append(Port(137, "udp", "netbios-ns", h.netbios))
            h.ports.sort(key=lambda x: x.port)

    # flows
    servers = {(ip, p.port) for ip, h in hosts.items() for p in h.ports}
    agg = defaultdict(lambda: [0, 0, set()])
    self_ips = {i["ip"] for i in ifaces}
    for client, server, port, proto in socket_flows(self_ips):
        rec = agg[(client, server, port, proto)]
        rec[0] += 1
        rec[2].add("socket")
    capture_iface = (opts.interface[0] if opts.interface else gw_dev or (ifaces[0]["name"] if ifaces else ""))
    if opts.capture > 0 and not scan.privileged:
        scan.notes.append("Passive capture skipped: it needs root (run with sudo).")
        info("passive capture needs root; showing this host's own connections only")
    elif opts.capture > 0 and not hasattr(socket, "AF_PACKET"):
        scan.notes.append("Passive capture is only supported on Linux.")
    elif opts.capture > 0 and capture_iface:
        with phase("Capture", total=opts.capture) as ph:
            ph.note(f"listening on {capture_iface}")
            res = await loop.run_in_executor(
                None, sniff, capture_iface, opts.capture,
                lambda s: ph.progress and ph.progress.update(ph.task, completed=s))
            ph.advance(opts.capture)
            servers |= res["synack"]
            for (src, sport, dst, dport, proto), (n, b) in res["pkts"].items():
                c, s_, port = orient(src, sport, dst, dport, proto, servers)
                rec = agg[(c, s_, port, proto)]
                rec[0] += n
                rec[1] += b
                rec[2].add("capture")
            passive = 0
            for ip, mac in list(res["arp"].items()) + list(res["ipmac"].items()):
                if ip in hosts or ip == gw:
                    if ip in hosts and not hosts[ip].mac:
                        hosts[ip].mac = mac
                    continue
                if any(ipaddress.ip_address(ip) in n for n in on_link if n in targets) and not is_group_addr(ip):
                    h = host(ip)
                    h.mac = mac
                    h.saw("passive")
                    passive += 1
            if passive:
                silent = [h for h in hosts.values() if "passive" in h.seen_by]
                vendors = oui.lookup_many([h.mac for h in silent])
                for h in silent:
                    h.vendor = h.vendor or vendors.get(h.mac, "")
            scan.vlan_tags = {str(k): v for k, v in res["vlans"].items()}
            scan.capture_s = opts.capture
            ph.summary = (f"{sum(n for n, _ in res['pkts'].values()):,} packets · {len(res['pkts'])} tuples"
                          + (f" · {passive} silent hosts" if passive else ""))
    scan.flows = [Flow(c, s_, port, proto, n, b, "+".join(sorted(src)))
                  for (c, s_, port, proto), (n, b, src) in agg.items()]

    if trace_task:
        with phase("Route") as ph:
            scan.route = await trace_task
            ph.summary = (" → ".join(h["ip"] or "*" for h in scan.route[:5]) or "no route data")

    scan.hosts = list(hosts.values())
    finalise(scan)
    scan.finished = datetime.now().isoformat(timespec="seconds")
    scan.duration_s = round(time.monotonic() - t0, 1)
    if not scan.privileged:
        scan.notes.append("Ran unprivileged: discovery used ICMP and the kernel ARP cache; no arp-scan and no passive capture.")
    pool.shutdown(wait=False)
    return scan


# ─────────────────────────────── demo data ─────────────────────────────────


def demo_scan() -> Scan:
    rnd = random.Random(7)

    def mac(prefix=None):
        p = prefix or f"{rnd.randrange(0, 256) & 0xFC:02x}{rnd.randrange(256):02x}{rnd.randrange(256):02x}"
        p = p.replace(":", "").lower()
        return ":".join([p[0:2], p[2:4], p[4:6]] + [f"{rnd.randrange(256):02x}" for _ in range(3)])

    def mk(ip, name, vendor, ports, ttl=64, oui=None, **kw):
        h = Host(ip=ip, hostname=name, vendor=vendor, ttl=ttl, rtt_ms=round(rnd.uniform(0.2, 4.0), 2),
                 mac=mac(oui), subnet="10.20.0.0/24" if ip.startswith("10.20.0.") else "192.168.50.0/24",
                 seen_by=["icmp", "arp"], **kw)
        h.ports = [Port(p, "tcp", SERVICES.get(p, ""), b) for p, b in sorted(ports)]
        return h

    H = [
        mk("10.20.0.1", "gw.office.lan", "Ubiquiti", [(22, "SSH-2.0-OpenSSH_8.4"), (53, ""), (80, "UniFi OS"), (443, "UniFi OS")], oui="245ebe", is_gateway=True),
        mk("10.20.0.2", "sw-core.office.lan", "Ubiquiti", [(22, "SSH-2.0-dropbear_2020.81"), (443, "UniFi Switch")], oui="788a20"),
        mk("10.20.0.3", "sw-floor2.office.lan", "Ubiquiti", [(22, "SSH-2.0-dropbear_2020.81")], oui="788a20"),
        mk("10.20.0.4", "ap-lobby.office.lan", "Ubiquiti", [(22, "SSH-2.0-dropbear_2020.81")], oui="f09fc2"),
        mk("10.20.0.5", "ap-floor2.office.lan", "Ubiquiti", [(22, "SSH-2.0-dropbear_2020.81")], oui="f09fc2"),
        mk("10.20.0.10", "hv01.office.lan", "Supermicro", [(22, "SSH-2.0-OpenSSH_9.2p1 Debian-2"), (111, ""), (3128, ""), (8006, "Proxmox Virtual Environment · pve-api-daemon/3.0")]),
        mk("10.20.0.11", "dc01.office.lan", "VMware", [(53, ""), (88, ""), (135, ""), (139, ""), (389, ""), (445, ""), (636, ""), (3268, ""), (3389, "")], ttl=128, oui="005056", netbios="DC01"),
        mk("10.20.0.12", "nas01.office.lan", "Synology", [(22, "SSH-2.0-OpenSSH_8.2"), (80, "Synology DiskStation · nginx"), (139, ""), (443, "Synology DiskStation · nginx"), (445, ""), (2049, ""), (5000, "Synology DiskStation · nginx"), (5001, "Synology DiskStation · nginx")], oui="001132"),
        mk("10.20.0.13", "db01.office.lan", "VMware", [(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"), (5432, "")], oui="005056"),
        mk("10.20.0.14", "erp.office.lan", "VMware", [(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"), (80, "nginx/1.24.0"), (443, "R-ERP Portal · nginx/1.24.0")], oui="005056"),
        mk("10.20.0.40", "prn-hp-m479.office.lan", "HP", [(80, "HP Color LaserJet MFP M479fdw"), (443, "HP Color LaserJet MFP M479fdw"), (515, ""), (631, ""), (9100, "")], ttl=255),
        mk("10.20.0.41", "prn-brother.office.lan", "Brother", [(80, "Brother HL-L8360CDW series · debut/1.30"), (631, ""), (9100, "")], ttl=255, oui="008077"),
        mk("10.20.0.60", "sonos-conf", "Sonos", [(1400, "Sonos")], oui="5caafd"),
        mk("10.20.0.61", "chromecast-boardroom", "Google", [(8008, ""), (8009, "")]),
        mk("10.20.0.62", "", "Espressif", [(80, "Tasmota")], oui="240ac4"),
        mk("10.20.0.63", "thermostat", "ecobee", [(443, "")]),
    ]
    for i in range(4):
        H.append(mk(f"10.20.0.{50 + i}", f"phone-{101 + i}", "Yealink", [(80, "Yealink T54W"), (443, "Yealink T54W"), (5060, "")], oui="805ec0"))
    for i in range(4):
        H.append(mk(f"10.20.0.{70 + i}", f"cam-{['lobby', 'dock', 'lot-n', 'lot-s'][i]}", "Hikvision", [(80, "Hikvision Web Client"), (554, ""), (8000, "")], oui="4419b6"))
    H.append(mk("10.20.0.75", "nvr01", "Hikvision", [(80, "Hikvision NVR"), (443, ""), (554, ""), (8000, "")], oui="4419b6"))
    names = ["eng-ws01", "eng-ws02", "eng-ws03", "eng-ws04", "acct-ws01", "acct-ws02", "ops-ws01", "ops-ws02",
             "ops-ws03", "sales-lt01", "sales-lt02", "sales-lt03", "ceo-lt01", "recept-ws01"]
    for i, n in enumerate(names):
        ports = [(135, ""), (139, ""), (445, "")] + ([(3389, "")] if i % 3 == 0 else [])
        H.append(mk(f"10.20.0.{100 + i}", f"{n}.office.lan", rnd.choice(["Dell", "Lenovo", "Intel Corporate"]), ports, ttl=128, netbios=n.upper()))
    for i in range(3):
        H.append(mk(f"10.20.0.{130 + i}", f"mbp-{['jlee', 'amorgan', 'design'][i]}", "Apple", [(7000, "AirTunes/775.3.1"), (22, "")] if i == 2 else [(7000, "AirTunes/775.3.1")]))
    for i in range(5):
        h = mk(f"10.20.0.{150 + i * 3}", "", "Private MAC", [(62078, "")] if i < 3 else [], random_mac=True)
        h.mac = "da" + h.mac[2:]
        H.append(h)
    H.append(mk("10.20.0.200", "", "", [], ttl=64))
    H.append(mk("10.20.0.201", "", "Texas Instruments", [(80, "")], ttl=255))
    me = mk("10.20.0.108", "ops-ws03", "Dell", [(22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")], ttl=64, is_self=True)
    H = [h for h in H if h.ip != me.ip] + [me]
    H += [
        mk("192.168.50.1", "lab-gw", "MikroTik", [(22, ""), (8291, ""), (80, "RouterOS router configuration page")], ttl=255),
        mk("192.168.50.10", "pi-hole", "Raspberry Pi", [(22, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"), (53, ""), (80, "Pi-hole · lighttpd/1.4.69")], oui="dca632"),
        mk("192.168.50.11", "plc-test", "Siemens", [(102, ""), (80, "")], ttl=30),
        mk("192.168.50.20", "build01", "QEMU", [(22, "SSH-2.0-OpenSSH_9.2p1 Debian-2"), (8080, "Jenkins")], oui="525400"),
    ]

    scan = Scan(started="2026-10-16T09:41:12", finished="2026-10-16T09:42:20", duration_s=68.4,
                scanner="ops-ws01", privileged=True, gateway="10.20.0.1", dns=["10.20.0.11", "1.1.1.1"],
                interfaces=[{"name": "eth0", "mac": me.mac, "ip": "10.20.0.108", "cidr": "10.20.0.0/24", "prefix": 24},
                            {"name": "eth1", "mac": mac(), "ip": "192.168.50.5", "cidr": "192.168.50.0/24", "prefix": 24}],
                subnets=["10.20.0.0/24", "192.168.50.0/24"],
                route=[{"hop": 1, "ip": "10.20.0.1"}, {"hop": 2, "ip": "100.64.0.1"}, {"hop": 3, "ip": "203.0.113.9"},
                       {"hop": 4, "ip": ""}, {"hop": 5, "ip": "198.51.100.30"}],
                hosts=H, capture_s=60, ports_scanned=len(TOP_TCP), vlan_tags={})
    ws = [h.ip for h in H if h.ip.startswith("10.20.0.1") and 100 <= int(h.ip.split(".")[-1]) < 140]
    F = []

    def f(src, dst, port, proto="tcp", n=None):
        n = n or rnd.randint(40, 4000)
        F.append(Flow(src, dst, port, proto, n, n * rnd.randint(120, 1400), "capture"))
    for w in ws:
        f(w, "10.20.0.11", 53, "udp"); f(w, "10.20.0.11", 88); f(w, "10.20.0.11", 389)
        if rnd.random() < .8:
            f(w, "10.20.0.12", 445, n=rnd.randint(2000, 90000))
        if rnd.random() < .5:
            f(w, "10.20.0.40", 9100)
        f(w, "10.20.0.14", 443)
        f(w, "203.0.113.50", 443, n=rnd.randint(3000, 50000))
    f("10.20.0.105", "10.20.0.41", 631)
    f("10.20.0.14", "10.20.0.13", 5432, n=60000)
    f("10.20.0.10", "10.20.0.12", 2049, n=120000)
    f("10.20.0.75", "10.20.0.70", 554, n=90000); f("10.20.0.75", "10.20.0.71", 554, n=88000)
    f("10.20.0.75", "10.20.0.72", 554, n=70000); f("10.20.0.75", "10.20.0.73", 554, n=65000)
    for p in range(4):
        f(f"10.20.0.{50 + p}", "198.51.100.77", 5061)
    f("10.20.0.130", "224.0.0.251", 5353, "udp"); f("10.20.0.131", "224.0.0.251", 5353, "udp")
    f("10.20.0.60", "224.0.0.251", 5353, "udp"); f("10.20.0.61", "239.255.255.250", 1900, "udp")
    f("10.20.0.103", "239.255.255.250", 1900, "udp"); f("10.20.0.153", "255.255.255.255", 67, "udp", 12)
    f("10.20.0.62", "203.0.113.80", 8883)
    f("10.20.0.60", "203.0.113.120", 443)
    f("10.20.0.108", "10.20.0.2", 22, n=300)
    f("10.20.0.10", "10.20.0.11", 53, "udp")
    f("10.20.0.10", "10.20.0.11", 389)
    f("192.168.50.20", "10.20.0.12", 445, n=4000)
    f("192.168.50.20", "203.0.113.200", 443)
    scan.flows = F
    scan.notes.append("Demo data: a synthetic 70-host office network; nothing was scanned.")
    finalise(scan)
    return scan


# ───────────────────────────── HTML report ─────────────────────────────────


def esc(s) -> str:
    return html.escape(str(s), quote=True)


def trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def anchor(ip: str) -> str:
    return "h-" + ip.replace(".", "-")


def zone_label(z: str) -> str:
    return ZONE[z][1] if z in ZONE else PSEUDO_ZONES.get(z, z)


def host_tip(h: Host) -> str:
    lines = [f"{h.ip}" + (f"  ·  {h.name}" if h.name else "") + ("  (this host)" if h.is_self else "")]
    lines.append(" · ".join(x for x in (h.vendor, ROLES[h.role][1], zone_label(h.zone)) if x))
    meta = [x for x in (h.os_guess, f"TTL {h.ttl}" if h.ttl else "", f"{h.rtt_ms} ms" if h.rtt_ms else "", h.mac) if x]
    if meta:
        lines.append(" · ".join(meta))
    if h.ports:
        lines.append("Open: " + ", ".join(f"{p.port}{'/' + p.proto if p.proto != 'tcp' else ''} {p.service}".strip() for p in h.ports[:14])
                     + (" …" if len(h.ports) > 14 else ""))
    return "\n".join(lines)


class Endpoints:
    """Maps flow endpoints to hosts or pseudo-nodes (internet, multicast)."""

    def __init__(self, scan: Scan):
        self.hosts = {h.ip: h for h in scan.hosts}
        self.nets = [ipaddress.ip_network(s) for s in scan.subnets]

    def key(self, ip: str) -> str:
        if ip in self.hosts:
            return ip
        if is_group_addr(ip):
            return "mcast:" + ip
        a = ipaddress.ip_address(ip)
        if any(a in n for n in self.nets) or is_lan(ip):
            return ip
        return "internet"

    def zone(self, key: str) -> str:
        if key == "internet":
            return "internet"
        if key.startswith("mcast:"):
            return "multicast"
        h = self.hosts.get(key)
        return h.zone if h else "unassigned"

    def label(self, key: str) -> tuple:
        if key == "internet":
            return "Internet", "external hosts"
        if key.startswith("mcast:"):
            ip = key[6:]
            kind = "Broadcast" if ip.endswith(".255") else "Multicast"
            return kind, ip
        h = self.hosts.get(key)
        if h:
            return (h.name.split(".")[0] if h.name else h.ip), (h.ip if h.name else (h.vendor or ROLES[h.role][1]))
        return key, "not discovered"


def svg_topology(scan: Scan) -> str:
    W, PAD = 1120, 24
    CW, CH, GAP = 206, 40, 8
    out, y = [], PAD
    hosts = {h.ip: h for h in scan.hosts}
    gw = hosts.get(scan.gateway)
    me = next((h for h in scan.hosts if h.is_self), None)
    top = gw or me

    # uplink chain: gateway → hops → internet
    chain = []
    if top:
        chain.append(("Gateway" if gw else "This host", top.ip, top.name or top.vendor, top))
    hops = [r for r in scan.route if r["ip"] != scan.gateway][:6]
    shown = hops[:2]
    for r in shown:
        try:
            kind = "ISP CGNAT" if ipaddress.ip_address(r["ip"]) in ipaddress.ip_network("100.64.0.0/10") else \
                ("Private hop" if is_lan(r["ip"]) else "Upstream")
        except ValueError:
            kind = "Upstream"
        chain.append((f"Hop {r['hop']} · {kind}", r["ip"] or "no reply", "", None))
    if gw or hops:
        extra = len(hops) - len(shown)
        chain.append(("Internet", f"+{extra} more hops" if extra > 0 else "", "", None))
    NW, NH, NG = 196, 54, 50
    for i, (title, l1, l2, h) in enumerate(chain):
        x = PAD + i * (NW + NG)
        if i:
            dashed = ' stroke-dasharray="4 4"' if title == "Internet" else ""
            out.append(f'<line x1="{x - NG}" y1="{y + NH / 2}" x2="{x}" y2="{y + NH / 2}" class="link"{dashed}/>')
        cls = "node gw" if h is not None else ("node cloud" if title == "Internet" else "node")
        tip = host_tip(h) if h else f"{title}\n{l1}"
        tag = f'<a href="#{anchor(h.ip)}">' if h else ""
        out.append(f'{tag}<g class="{cls}" data-tip="{esc(tip)}"><rect x="{x}" y="{y}" width="{NW}" height="{NH}" rx="{27 if title == "Internet" else 10}"/>'
                   f'<text x="{x + 14}" y="{y + 21}" class="nt">{esc(title)}</text>'
                   f'<text x="{x + 14}" y="{y + 40}" class="ip">{esc(trunc(l1, 26))}'
                   + (f'<tspan class="nm" dx="6">{esc(trunc(l2, 14))}</tspan>' if l2 else "")
                   + f'</text></g>{"</a>" if h else ""}')
    if scan.dns:
        out.append(f'<text x="{W - PAD}" y="{y + NH + 18}" class="cap" text-anchor="end">DNS {esc(", ".join(scan.dns[:3]))}</text>')
    spine_x, spine_top = PAD + 16, y + NH
    y += NH + 34

    subnets = sorted(scan.subnets, key=lambda s: (scan.gateway == "" or ipaddress.ip_address(scan.gateway) not in ipaddress.ip_network(s), s)) \
        if scan.gateway else list(scan.subnets)
    last_bar_mid = spine_top
    for cidr in subnets:
        members = [h for h in scan.hosts if h.subnet == cidr and h is not top]
        iface = next((i["name"] for i in scan.interfaces if i["cidr"] == cidr), "routed")
        bx, bw, bh = PAD + 34, W - 2 * PAD - 34, 36
        mid = y + bh / 2
        out.append(f'<line x1="{spine_x}" y1="{mid}" x2="{bx}" y2="{mid}" class="link"/>')
        last_bar_mid = mid
        count = len(members) + (1 if top and top.subnet == cidr else 0)
        out.append(f'<rect x="{bx}" y="{y}" width="{bw}" height="{bh}" rx="8" class="bar"/>'
                   f'<text x="{bx + 14}" y="{y + 23}" class="ip strong">{esc(cidr)}</text>'
                   f'<text x="{bx + 14 + 9 * len(cidr)}" y="{y + 23}" class="cap">{esc(iface)} · {count} host{"s" * (count != 1)}</text>')
        y += bh + 30
        # zone cards packed onto shelves, each shelf hanging off its own bus
        groups = defaultdict(list)
        for h in members:
            groups[h.zone].append(h)
        cards = []
        for z in sorted(groups, key=ZONE_ORDER.get):
            n = len(groups[z])
            cols = 1 if n <= 4 else 2 if n <= 12 else 3 if n <= 30 else 4
            rows = math.ceil(n / cols)
            cards.append((z, sorted(groups[z], key=lambda h: ip_key(h.ip)), cols,
                          cols * CW + (cols - 1) * GAP + 24, 44 + rows * (CH + GAP) - GAP + 12))
        local_x, x0, xmax = bx + 16, bx + 34, W - PAD
        shelves, cur, cx = [], [], x0
        for c in cards:
            if cur and cx + c[3] > xmax:
                shelves.append(cur)
                cur, cx = [], x0
            cur.append((cx, c))
            cx += c[3] + 18
        if cur:
            shelves.append(cur)
        if not shelves:
            out.append(f'<text x="{x0}" y="{y}" class="cap">No other hosts found on this segment</text>')
            y += 24
        local_top = y - 30
        for shelf in shelves:
            bus_y = y - 14
            out.append(f'<line x1="{local_x}" y1="{local_top}" x2="{local_x}" y2="{bus_y}" class="link"/>')
            local_top = bus_y
            last_cx = shelf[-1][0] + shelf[-1][1][3] / 2
            out.append(f'<line x1="{local_x}" y1="{bus_y}" x2="{last_cx}" y2="{bus_y}" class="link"/>')
            shelf_h = 0
            for cx, (z, hs, cols, w, hgt) in shelf:
                out.append(f'<line x1="{cx + w / 2}" y1="{bus_y}" x2="{cx + w / 2}" y2="{y}" class="link"/>')
                vlan = ZONE[z][2]
                out.append(f'<g class="card"><rect x="{cx}" y="{y}" width="{w}" height="{hgt}" rx="10" class="card-bg"/>'
                           f'<rect x="{cx}" y="{y}" width="{w}" height="4" rx="2" style="fill:var(--z-{z})"/>'
                           f'<text x="{cx + 12}" y="{y + 26}" class="nt">{esc(ZONE[z][1])}'
                           f'<tspan class="cap" dx="8">{len(hs)}</tspan></text>'
                           + (f'<text x="{cx + w - 12}" y="{y + 26}" class="cap" text-anchor="end">VLAN {vlan}</text>' if vlan else "")
                           + "</g>")
                for i, h in enumerate(hs):
                    hx = cx + 12 + (i % cols) * (CW + GAP)
                    hy = y + 40 + (i // cols) * (CH + GAP)
                    out.append(chip(h, hx, hy, CW, CH))
                shelf_h = max(shelf_h, hgt)
            y += shelf_h + 40
        y += 6
    if subnets:
        out.insert(0, f'<line x1="{spine_x}" y1="{spine_top}" x2="{spine_x}" y2="{last_bar_mid}" class="link"/>')
    H = y
    return (f'<svg class="topo" viewBox="0 0 {W} {H}" role="img" aria-label="Network topology block diagram">'
            + "".join(out) + "</svg>")


def chip(h: Host, x, y, w, hgt) -> str:
    badge = ROLES[h.role][0]
    label = h.name.split(".")[0] if h.name else (h.vendor or "unidentified")
    if h.is_self:
        label = "this host · " + label
    return (f'<a href="#{anchor(h.ip)}"><g class="chip" data-tip="{esc(host_tip(h))}">'
            f'<rect x="{x}" y="{y}" width="{w}" height="{hgt}" rx="7" class="chip-bg{" self" if h.is_self else ""}"/>'
            f'<rect x="{x + 6}" y="{y + 7}" width="36" height="{hgt - 14}" rx="5" class="badge" style="fill:var(--z-{h.zone});stroke:var(--z-{h.zone})"/>'
            f'<text x="{x + 24}" y="{y + hgt / 2 + 4}" class="abbr" text-anchor="middle">{esc(badge)}</text>'
            f'<text x="{x + 50}" y="{y + 17}" class="ip">{esc(h.ip)}</text>'
            f'<text x="{x + 50}" y="{y + 32}" class="nm">{esc(trunc(label, 23))}</text>'
            + (f'<text x="{x + w - 8}" y="{y + 17}" class="cap" text-anchor="end">{len(h.ports)}</text>' if h.ports else "")
            + "</g></a>")


def svg_address_map(scan: Scan, cidr: str) -> tuple:
    net = ipaddress.ip_network(cidr)
    hosts = {h.ip: h for h in scan.hosts if h.subnet == cidr}
    blocks = list(net.subnets(new_prefix=24)) if net.prefixlen < 24 else [net]
    blocks = [b for b in blocks if any(ipaddress.ip_address(ip) in b for ip in hosts)][:16] or blocks[:1]
    svgs = []
    COLS, CW, CH, G = 32, 31, 26, 3
    for b in blocks:
        cells, n = [], b.num_addresses
        rows = math.ceil(n / COLS)
        for i, addr in enumerate(b):
            ip = str(addr)
            x, y = (i % COLS) * (CW + G), (i // COLS) * (CH + G) + 4
            last = ip.split(".")[-1]
            h = hosts.get(ip)
            if addr in (net.network_address, net.broadcast_address) and net.prefixlen < 31:
                what = "network address" if addr == net.network_address else "broadcast address"
                cells.append(f'<g data-tip="{ip}\n{what}"><rect x="{x}" y="{y}" width="{CW}" height="{CH}" rx="4" class="cell reserved"/>'
                             f'<text x="{x + CW / 2}" y="{y + 17}" class="cn muted" text-anchor="middle">{last}</text></g>')
            elif h:
                cls = "cell used" + (" gw" if h.is_gateway else "") + (" me" if h.is_self else "")
                cells.append(f'<a href="#{anchor(ip)}"><g data-tip="{esc(host_tip(h))}"><rect x="{x}" y="{y}" width="{CW}" height="{CH}" rx="4" class="{cls}" '
                             f'style="fill:var(--z-{h.zone});stroke:var(--z-{h.zone})"/>'
                             f'<text x="{x + CW / 2}" y="{y + 17}" class="cn" text-anchor="middle">{last}</text></g></a>')
            else:
                cells.append(f'<g data-tip="{ip}\nfree"><rect x="{x}" y="{y}" width="{CW}" height="{CH}" rx="4" class="cell"/>'
                             f'<text x="{x + CW / 2}" y="{y + 17}" class="cn muted" text-anchor="middle">{last}</text></g>')
        w, hgt = COLS * (CW + G) - G, rows * (CH + G) + 4
        title = f'<div class="block-title mono">{b}</div>' if len(blocks) > 1 else ""
        svgs.append(f'{title}<svg class="amap" viewBox="0 0 {w} {hgt}" role="img" aria-label="Address map {b}">{"".join(cells)}</svg>')

    # largest free runs
    used = {ip_key(ip) for ip in hosts}
    runs, start = [], None
    usable = list(net.hosts()) if net.prefixlen < 31 else list(net)
    for addr in usable + [None]:
        k = int(addr) if addr is not None else None
        if k is not None and k not in used:
            start = start if start is not None else k
            end = k
        elif start is not None:
            runs.append((end - start + 1, start, end))
            start = None
    runs.sort(reverse=True)
    free = len(usable) - len(used & {int(a) for a in usable})
    return "".join(svgs), runs[:6], free, len(usable)


def aggregate_flows(scan: Scan, ep: Endpoints) -> list:
    agg = defaultdict(lambda: [0, 0, set()])
    for f in scan.flows:
        k = (ep.key(f.src), ep.key(f.dst), f.dport, f.proto)
        agg[k][0] += f.packets
        agg[k][1] += f.bytes
        agg[k][2].add((f.src, f.dst))
    return sorted(([*k, n, b, len(pairs)] for k, (n, b, pairs) in agg.items()), key=lambda r: -r[4])


def svg_flows(scan: Scan, ep: Endpoints, rows: list) -> str:
    if not rows:
        return ""
    W, PAD, NW, RH = 1120, 8, 270, 34
    left_tot, right_tot = Counter(), Counter()
    for c, s, port, proto, n, b, _ in rows:
        left_tot[c] += n
        right_tot[s] += n
    L = [k for k, _ in left_tot.most_common(26)]
    R = [k for k, _ in right_tot.most_common(26)]
    edges = [r for r in rows if r[0] in L and r[1] in R][:90]
    hidden = len(rows) - len(edges)
    services = defaultdict(set)
    for c, s, port, proto, *_ in edges:
        services[s].add(f"{SERVICES.get(port, port) if port else proto}")
    H = max(len(L), len(R)) * RH + 30
    ly = {k: 24 + i * RH + (H - 24 - len(L) * RH) / 2 for i, k in enumerate(L)}
    ry = {k: 24 + i * RH + (H - 24 - len(R) * RH) / 2 for i, k in enumerate(R)}
    out = [f'<text x="{PAD}" y="12" class="cap">INITIATED BY</text>',
           f'<text x="{W - PAD}" y="12" class="cap" text-anchor="end">SERVED BY</text>']
    maxn = max(r[4] for r in edges) if edges else 1
    x1, x2 = PAD + NW, W - PAD - NW
    for c, s, port, proto, n, b, pairs in sorted(edges, key=lambda r: r[4]):
        y1, y2 = ly[c] + 12, ry[s] + 12
        sw = 1.2 + 7 * math.log1p(n) / math.log1p(maxn)
        mx = (x1 + x2) / 2
        svc = SERVICES.get(port, "") if port else ""
        tip = (f"{ep.label(c)[0]} → {ep.label(s)[0]}\n{proto}/{port} {svc}".rstrip()
               + f"\n{n:,} packets · {fmt_bytes(b)}" + (f" · {pairs} host pairs" if pairs > 1 else ""))
        out.append(f'<path d="M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}" class="edge" data-a="{esc(c)}" data-b="{esc(s)}" '
                   f'style="stroke:var(--z-{ep.zone(c)});stroke-width:{sw:.1f}" data-tip="{esc(tip)}"/>')

    def node(k, x, y, side):
        z = ep.zone(k)
        t1, t2 = ep.label(k)
        if side == "r" and services.get(k):
            t2 = trunc(", ".join(sorted(services[k])), 30)
        tip = host_tip(ep.hosts[k]) if k in ep.hosts else f"{t1}\n{t2}"
        sx = x if side == "l" else x + NW - 4
        tx = x + 14 if side == "l" else x + 10
        return (f'<g class="fnode" data-k="{esc(k)}" data-tip="{esc(tip)}"><rect x="{x}" y="{y}" width="{NW}" height="24" rx="5" class="chip-bg"/>'
                f'<rect x="{sx}" y="{y}" width="4" height="24" rx="2" style="fill:var(--z-{z})"/>'
                f'<text x="{tx}" y="{y + 16}" class="nm2"><tspan class="strong">{esc(trunc(t1, 20))}</tspan>'
                f'<tspan class="cap" dx="7">{esc(trunc(t2, 30 - min(len(t1), 20)))}</tspan></text></g>')
    out += [node(k, PAD, ly[k], "l") for k in L]
    out += [node(k, W - PAD - NW, ry[k], "r") for k in R]
    note = f'<p class="cap">{hidden} smaller conversations not drawn; all are listed in the table below.</p>' if hidden > 0 else ""
    return (f'<svg class="flows" viewBox="0 0 {W} {H}" role="img" aria-label="Flow diagram">{"".join(out)}</svg>{note}')


def zone_rules(rows: list, ep: Endpoints) -> list:
    rules = defaultdict(lambda: [0, set(), set()])
    for c, s, port, proto, n, b, _ in rows:
        zc, zs = ep.zone(c), ep.zone(s)
        if zc == zs or zs == "multicast" or (proto not in ("tcp", "udp")):
            continue
        r = rules[(zc, zs, proto, port)]
        r[0] += n
        r[1].add(c)
        r[2].add(s)
    order = lambda z: ZONE_ORDER.get(z, 50 if z == "internet" else 60)
    return sorted(([zc, zs, proto, port, n, cs, ss] for (zc, zs, proto, port), (n, cs, ss) in rules.items()),
                  key=lambda r: (order(r[0]), order(r[1]), r[3]))


def zone_dot(z: str) -> str:
    return f'<span class="dot" style="background:var(--z-{z})"></span>'


def build_report(scan: Scan) -> str:
    ep = Endpoints(scan)
    rows = aggregate_flows(scan, ep)
    hosts = scan.hosts
    open_svc = sum(len(h.ports) for h in hosts)
    zones_present = [z for z in ZONES if any(h.zone == z[0] for h in hosts)]
    rules = zone_rules(rows, ep)
    disco = defaultdict(lambda: [set(), 0])
    for c, s, port, proto, n, b, _ in rows:
        if port in DISCOVERY and proto == "udp":
            d = disco[DISCOVERY[port][0]]
            d[0].add(c)
            d[1] += n

    def kpi(v, label, sub=""):
        return f'<div class="kpi"><div class="kv">{v}</div><div class="kl">{label}</div>{f"<div class=ks>{sub}</div>" if sub else ""}</div>'

    started = scan.started.replace("T", " ")
    kpis = "".join([
        kpi(len(hosts), "Hosts found", f"{sum(1 for h in hosts if h.name)} with names"),
        kpi(len(scan.subnets), "Subnets", ", ".join(scan.subnets[:2]) + (" …" if len(scan.subnets) > 2 else "")),
        kpi(open_svc, "Open services", f"{scan.ports_scanned} ports probed per host"),
        kpi(len(rows), "Conversations", f"{scan.capture_s}s capture" if scan.capture_s else "local sockets only"),
        kpi(len(rules), "Cross-zone rules", "under the proposed plan"),
    ])

    legend = "".join(f'<span class="lg">{zone_dot(z[0])}{esc(z[1])}</span>' for z in zones_present)

    # zones / segmentation plan
    zcards = []
    for z in zones_present:
        members = [h for h in hosts if h.zone == z[0]]
        items = "".join(f'<li><a href="#{anchor(h.ip)}" class="mono">{h.ip}</a> <span class="muted">{esc(trunc(h.name.split(".")[0] if h.name else (h.vendor or ROLES[h.role][1]), 26))}</span></li>'
                        for h in members[:8])
        more = f'<li class="muted">+ {len(members) - 8} more</li>' if len(members) > 8 else ""
        vlan = f"VLAN {z[2]}" if z[2] else "review"
        zcards.append(f'<div class="zone"><div class="zbar" style="background:var(--z-{z[0]})"></div>'
                      f'<div class="zhead"><span class="zname">{esc(z[1])}</span><span class="zvlan mono">{vlan}</span></div>'
                      f'<div class="zdesc">{esc(z[3])}</div><div class="zcount">{len(members)} device{"s" * (len(members) != 1)}</div>'
                      f'<ul>{items}{more}</ul></div>')

    def ep_list(keys, k=3):
        keys = sorted(keys, key=lambda x: (x == "internet", ip_key(x) if not x.startswith(("mcast", "internet")) else 0))
        names = [ep.label(x)[0] for x in keys[:k]]
        return esc(", ".join(names)) + (f' <span class="muted">+{len(keys) - k}</span>' if len(keys) > k else "")

    rule_rows = "".join(
        f'<tr><td>{zone_dot(zc) if zc in ZONE else ""}{esc(zone_label(zc))}</td><td class="arrow">→</td>'
        f'<td>{zone_dot(zs) if zs in ZONE else ""}{esc(zone_label(zs))}</td>'
        f'<td class="mono">{proto}/{port}</td><td>{esc(SERVICES.get(port, ""))}</td>'
        f'<td>{ep_list(cs)}</td><td>{ep_list(ss)}</td><td class="num">{n:,}</td></tr>'
        for zc, zs, proto, port, n, cs, ss in rules)
    rules_html = (f'<div class="tablewrap"><table class="sortable"><thead><tr><th>From</th><th></th><th>To</th><th>Port</th><th>Service</th>'
                  f'<th>Clients</th><th>Servers</th><th class="num">Packets</th></tr></thead><tbody>{rule_rows}</tbody></table></div>'
                  if rules else '<p class="empty">No cross-zone traffic was observed. Capture traffic (see below) to generate firewall rules.</p>')
    disco_html = ""
    if disco:
        items = "".join(
            f'<li><b>{esc(name)}</b> from {len(talkers)} device{"s" * (len(talkers) != 1)} '
            f'<span class="muted">({ep_list(talkers)})</span>. '
            f'{esc(next(v[1] for v in DISCOVERY.values() if v[0] == name).capitalize())}.</li>'
            for name, (talkers, n) in sorted(disco.items()))
        disco_html = (f'<div class="callout"><div class="ctitle">Breaks when you split VLANs</div>'
                      f'<p>These broadcast/multicast protocols stay inside one VLAN. Plan for each before you cut over.</p><ul>{items}</ul></div>')

    # flows
    flow_svg = svg_flows(scan, ep, rows)
    if not flow_svg:
        flow_svg = ('<p class="empty">No traffic recorded. Run as root with <code>--capture 120</code> to listen passively. '
                    'On a switched network you only see this host\'s traffic plus broadcast/multicast, so for a full picture '
                    'plug the scanner into a switch <b>mirror / SPAN port</b> that copies the uplink or the whole VLAN.</p>')
    flow_rows = "".join(
        f'<tr><td>{zone_dot(ep.zone(c)) if ep.zone(c) in ZONE else ""}{esc(ep.label(c)[0])} <span class="muted mono">{esc(c if c[0].isdigit() and ep.label(c)[0] != c else "")}</span></td>'
        f'<td>{zone_dot(ep.zone(s)) if ep.zone(s) in ZONE else ""}{esc(ep.label(s)[0])} <span class="muted mono">{esc(s if s[0].isdigit() and ep.label(s)[0] != s else (s[6:] if s.startswith("mcast:") else ""))}</span></td>'
        f'<td class="mono">{proto}/{port}</td><td>{esc(SERVICES.get(port, ""))}</td>'
        f'<td class="num" data-sort="{n}">{n:,}</td><td class="num" data-sort="{b}">{fmt_bytes(b)}</td></tr>'
        for c, s, port, proto, n, b, _ in rows[:400])
    flow_table = (f'<details><summary>All {len(rows)} conversations</summary><div class="tablewrap"><table class="sortable">'
                  f'<thead><tr><th>Client</th><th>Server</th><th>Port</th><th>Service</th><th class="num">Packets</th><th class="num">Bytes</th></tr></thead>'
                  f'<tbody>{flow_rows}</tbody></table></div></details>') if rows else ""

    # address maps
    amaps = []
    for cidr in scan.subnets:
        svg, runs, free, usable = svg_address_map(scan, cidr)
        runtxt = " ".join(
            f'<span class="pill mono">{ipaddress.ip_address(s)}{"" if s == e else " – ." + str(ipaddress.ip_address(e)).split(".")[-1]}'
            f' <span class="muted">({n})</span></span>' for n, s, e in runs[:5])
        amaps.append(f'<div class="amap-wrap"><div class="amap-head"><span class="mono strong">{cidr}</span>'
                     f'<span class="muted">{usable - free} used · {free} free of {usable}</span></div>{svg}'
                     f'<div class="free"><span class="muted">Largest free ranges</span> {runtxt or "none"}</div></div>')

    # services matrix
    with_ports = [h for h in hosts if h.ports]
    port_count = Counter(p.port for h in with_ports for p in h.ports)
    cols = sorted(p for p, _ in port_count.most_common(30))
    mrows = []
    for h in with_ports:
        have = {p.port: p for p in h.ports}
        cells = []
        for c in cols:
            dot = ""
            if c in have:
                tip = f"{h.ip}:{c} {SERVICES.get(c, '')}".strip() + ("\n" + have[c].banner if have[c].banner else "")
                dot = f'<span class="on" data-tip="{esc(tip)}"></span>'
            cells.append(f'<td class="mc">{dot}</td>')
        cells = "".join(cells)
        mrows.append(f'<tr><td class="mh"><a href="#{anchor(h.ip)}" class="mono">{h.ip}</a> <span class="muted">{esc(trunc(h.name.split(".")[0] if h.name else h.vendor, 18))}</span></td>{cells}</tr>')
    matrix = ('<div class="tablewrap"><table class="matrix"><thead><tr><th></th>'
              + "".join(f'<th class="mcol"><div><span class="mono">{c}</span> <span class="muted">{esc(SERVICES.get(c, ""))}</span></div></th>' for c in cols)
              + f'</tr></thead><tbody>{"".join(mrows)}</tbody></table></div>') if with_ports else '<p class="empty">No open TCP ports found.</p>'

    # inventory
    inv = []
    for h in hosts:
        chips = " ".join(
            f'<span class="port" data-tip="{esc((p.service + chr(10) if p.service else "") + p.banner)}">{p.port}{"/u" if p.proto == "udp" else ""}</span>'
            for p in h.ports)
        banners = "<br>".join(f'<span class="muted mono">{p.port}</span> {esc(p.banner)}' for p in h.ports if p.banner and p.proto == "tcp")
        flags = (" <span class=\"tag\">you</span>" if h.is_self else "") + (" <span class=\"tag\">gateway</span>" if h.is_gateway else "")
        inv.append(f'<tr id="{anchor(h.ip)}"><td class="mono" data-sort="{ip_key(h.ip)}">{h.ip}{flags}</td>'
                   f'<td>{esc(h.hostname)}{"<div class=muted>" + esc(h.netbios) + "</div>" if h.netbios and h.netbios.lower() not in h.hostname.lower() else ""}</td>'
                   f'<td class="mono small">{esc(h.mac)}</td><td>{esc(h.vendor)}</td>'
                   f'<td>{zone_dot(h.zone)}{esc(ROLES[h.role][1])}</td>'
                   f'<td data-sort="{ZONE_ORDER[h.zone]}">{esc(ZONE[h.zone][1])}</td><td>{esc(h.os_guess)}</td>'
                   f'<td class="num" data-sort="{h.rtt_ms or 0}">{h.rtt_ms if h.rtt_ms is not None else ""}</td>'
                   f'<td>{chips}{"<div class=banners>" + banners + "</div>" if banners else ""}'
                   f'{"<div class=muted>" + esc(h.snmp) + "</div>" if h.snmp else ""}</td>'
                   f'<td class="small muted">{esc(", ".join(h.seen_by))}</td></tr>')

    notes = list(scan.notes) + [
        "Roles and zones are heuristics from MAC vendor, open ports, banners and TTL. Treat them as a first draft and correct them before you plan VLANs.",
        "Hosts that block ICMP and sit behind a router (off-link) are only found if one of 22, 80, 443, 445, 3389 or 8080 responds.",
        "Traffic shows only what passed the capture interface during the capture window. Batch jobs, backups and monthly tasks may not show up.",
    ]
    if scan.vlan_tags:
        notes.append("802.1Q tags seen on the wire: " + ", ".join(f"VLAN {k} ({v} frames)" for k, v in sorted(scan.vlan_tags.items(), key=lambda kv: int(kv[0]))))

    body = f"""
<header>
  <div class="eyebrow">Network map</div>
  <h1>{esc(", ".join(scan.subnets))}</h1>
  <div class="meta">Scanned from <b>{esc(scan.scanner)}</b> · {esc(started)} · {scan.duration_s:.0f}s ·
  {"privileged" if scan.privileged else "unprivileged"} · lanmap {esc(scan.version)}</div>
  <div class="kpis">{kpis}</div>
</header>

<section>
  <h2>Topology</h2>
  <p class="lede">Uplink path from traceroute, then each subnet with its devices grouped by function. Hover for details, click to jump to the inventory.</p>
  <div class="legend">{legend}</div>
  <div class="figure scroll">{svg_topology(scan)}</div>
</section>

<section>
  <h2>Segmentation plan</h2>
  <p class="lede">A starting VLAN layout based on device function. The rules table lists every observed conversation that would cross a zone boundary. Under the new plan, each row needs a firewall allow rule.</p>
  <div class="zones">{"".join(zcards)}</div>
  {disco_html}
  <h3>Cross-zone traffic → firewall rules</h3>
  {rules_html}
</section>

<section>
  <h2>Data flows</h2>
  <p class="lede">Who opens connections to whom. Line weight is packet volume (log scale) and line colour is the client's zone. Hover over a device to isolate its traffic.</p>
  <div class="legend">{legend}<span class="lg">{zone_dot("internet")}Internet / multicast</span></div>
  <div class="figure scroll">{flow_svg}</div>
  {flow_table}
</section>

<section>
  <h2>Address space</h2>
  <p class="lede">Every address in each subnet, coloured by zone. Gaps are free addresses. Use them when you re-address devices into new VLANs.</p>
  <div class="legend">{legend}<span class="lg"><span class="dot hollow"></span>free</span></div>
  {"".join(amaps)}
</section>

<section>
  <h2>Services</h2>
  <p class="lede">Open TCP ports per host (most common {len(cols)} shown). Hover over a dot to see the service banner.</p>
  {matrix}
</section>

<section>
  <h2>Inventory</h2>
  <div class="toolbar"><input id="filter" type="search" placeholder="Filter hosts (IP, name, vendor, role, port)…" autocomplete="off"><span id="count" class="muted"></span></div>
  <div class="tablewrap"><table class="sortable" id="inventory"><thead><tr>
  <th>IP</th><th>Name</th><th>MAC</th><th>Vendor</th><th>Role</th><th>Zone</th><th>OS (guess)</th><th class="num">RTT ms</th><th>Open ports</th><th>Seen by</th>
  </tr></thead><tbody>{"".join(inv)}</tbody></table></div>
</section>

<section class="notes">
  <h2>Method &amp; caveats</h2>
  <ul>{"".join(f"<li>{esc(n)}</li>" for n in notes)}</ul>
</section>
"""
    return TEMPLATE.replace("{{TITLE}}", esc("Network map · " + ", ".join(scan.subnets))).replace("{{BODY}}", body)


def zone_css(mode: int) -> str:
    return "".join(f"--z-{z[0]}:{z[4][mode]};" for z in ZONES) + "--z-internet:var(--axis);--z-multicast:var(--axis);"


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<style>
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--surface-2:#f1f0ec;--ink:#0b0b0b;--ink-2:#52514e;--muted:#898781;
--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--accent:#2a78d6;--warn:#b26f00;--link:#c3c2b7;ZONES_LIGHT}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--surface-2:#232322;
--ink:#f0efec;--ink-2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#4a4a46;--border:rgba(255,255,255,.10);--accent:#3987e5;--warn:#fab219;--link:#4a4a46;ZONES_DARK}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--surface-2:#232322;--ink:#f0efec;--ink-2:#c3c2b7;--muted:#898781;
--grid:#2c2c2a;--axis:#4a4a46;--border:rgba(255,255,255,.10);--accent:#3987e5;--warn:#fab219;--link:#4a4a46;ZONES_DARK}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:1180px;margin:0 auto;padding:40px 24px 80px}
.mono,code{font-family:ui-monospace,"SF Mono","Cascadia Mono",Menlo,Consolas,monospace;font-variant-numeric:tabular-nums}
.muted{color:var(--muted)}.small{font-size:12px}.strong{font-weight:600}
a{color:inherit;text-decoration:none}a:hover .mono,a.mono:hover{color:var(--accent)}
header{margin-bottom:28px}
.eyebrow{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:600}
h1{font-size:28px;line-height:1.2;margin:6px 0 6px;font-weight:650;letter-spacing:-.01em}
.meta{color:var(--ink-2);font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:22px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.kv{font-size:28px;font-weight:650;line-height:1.1}.kl{font-size:13px;color:var(--ink-2);margin-top:4px}.ks{font-size:12px;color:var(--muted);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
section{margin-top:44px}
h2{font-size:19px;margin:0 0 4px;font-weight:650}
h3{font-size:15px;margin:28px 0 10px;font-weight:600}
.lede{color:var(--ink-2);margin:0 0 14px;max-width:820px}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin:0 0 10px;font-size:12.5px;color:var(--ink-2)}
.lg{display:inline-flex;align-items:center}
.dot{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:7px;flex:none;vertical-align:baseline}
.dot.hollow{border:1px solid var(--axis);background:transparent}
.figure{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px}
.scroll{overflow-x:auto}
.figure svg{display:block;width:100%;height:auto;min-width:760px}
svg text{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
svg .ip{font:12px ui-monospace,"SF Mono","Cascadia Mono",Menlo,Consolas,monospace;fill:var(--ink)}
svg .ip.strong{font-weight:600;font-size:13px}
svg .nm{font-size:11px;fill:var(--ink-2)}
svg .nm2{font-size:12px;fill:var(--ink)}
svg .nt{font-size:12.5px;font-weight:600;fill:var(--ink)}
svg .cap{font-size:11px;fill:var(--muted);font-weight:400}
svg .abbr{font-size:10px;font-weight:700;fill:var(--ink);letter-spacing:.02em}
svg .link{stroke:var(--link);stroke-width:1.5;fill:none}
svg .node rect{fill:var(--surface);stroke:var(--axis);stroke-width:1}
svg .node.gw rect{stroke:var(--z-infrastructure);stroke-width:1.5}
svg .node.cloud rect{fill:var(--surface-2)}
svg .bar{fill:var(--surface-2);stroke:var(--border)}
svg .card-bg{fill:var(--surface);stroke:var(--border)}
svg .chip-bg{fill:var(--page);stroke:var(--border)}
svg .chip-bg.self{stroke:var(--accent);stroke-width:1.5}
svg .badge{fill-opacity:.16;stroke-width:1}
svg .chip:hover .chip-bg,svg .fnode:hover .chip-bg{stroke:var(--accent)}
svg .cell{fill:var(--surface-2);stroke:var(--grid);stroke-width:1}
svg .cell.used{fill-opacity:.28;stroke-width:1.2}
svg .cell.reserved{fill:none;stroke:var(--grid);stroke-dasharray:3 2}
svg .cell.gw{stroke-width:2.5}
svg .cell.me{stroke-width:2.5;stroke-dasharray:4 2}
svg .cn{font:10px ui-monospace,Menlo,Consolas,monospace;fill:var(--ink)}
svg .cn.muted{fill:var(--muted)}
svg g[data-tip]:hover .cell{stroke:var(--accent)}
svg .edge{fill:none;stroke-opacity:.42;transition:stroke-opacity .12s}
svg .edge:hover{stroke-opacity:.95}
svg.flows.focus .edge{stroke-opacity:.06}
svg.flows.focus .edge.on{stroke-opacity:.9}
.zones{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.zone{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:0 16px 14px;overflow:hidden}
.zbar{height:4px;margin:0 -16px 12px}
.zhead{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.zname{font-weight:650}.zvlan{font-size:12px;color:var(--ink-2);background:var(--surface-2);border-radius:6px;padding:1px 7px}
.zdesc{font-size:12.5px;color:var(--muted);margin:2px 0 6px}
.zcount{font-size:12.5px;color:var(--ink-2);margin-bottom:6px}
.zone ul{list-style:none;margin:0;padding:0;font-size:12.5px}.zone li{padding:1px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.callout{margin-top:16px;border:1px solid var(--border);border-left:3px solid var(--warn);background:var(--surface);border-radius:10px;padding:12px 16px}
.ctitle{font-weight:650}.callout p{margin:2px 0 6px;color:var(--ink-2)}.callout ul{margin:0;padding-left:18px}.callout li{margin:3px 0}
.tablewrap{overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;font-weight:600;color:var(--ink-2);font-size:12px;padding:9px 12px;border-bottom:1px solid var(--grid);white-space:nowrap;position:sticky;top:0;background:var(--surface)}
table.sortable th{cursor:pointer;user-select:none}table.sortable th:hover{color:var(--ink)}
th.asc::after{content:" ↑"}th.desc::after{content:" ↓"}
td{padding:8px 12px;border-bottom:1px solid var(--grid);vertical-align:top}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--surface-2)}
tr:target{background:color-mix(in srgb,var(--accent) 12%,transparent)}
.num{text-align:right;font-variant-numeric:tabular-nums}
.arrow{color:var(--muted);padding-left:0;padding-right:0}
.port{display:inline-block;font:11.5px ui-monospace,Menlo,Consolas,monospace;background:var(--surface-2);border:1px solid var(--border);border-radius:5px;padding:0 5px;margin:1px 2px 1px 0}
.banners{font-size:12px;color:var(--ink-2);margin-top:4px;max-width:420px}
.tag{font-size:10.5px;font-family:system-ui,sans-serif;border:1px solid var(--accent);color:var(--accent);border-radius:4px;padding:0 4px;margin-left:4px;vertical-align:1px}
.matrix th.mcol{height:110px;vertical-align:bottom;padding:4px 0;position:static}
.matrix th.mcol>div{writing-mode:vertical-rl;transform:rotate(180deg);font-weight:500;font-size:11.5px;margin:0 auto}
.matrix td{padding:4px 0;text-align:center}.matrix td.mh{text-align:left;padding:4px 12px;white-space:nowrap}
.matrix .on{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--accent)}
.matrix tbody tr:hover td{background:var(--surface-2)}
.amap-wrap{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px 18px;margin-bottom:12px;overflow-x:auto}
.amap-head{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px;font-size:13px}
.amap{display:block;width:100%;height:auto;min-width:700px}
.block-title{font-size:12px;color:var(--muted);margin:8px 0 4px}
.free{margin-top:10px;font-size:12.5px;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.pill{background:var(--surface-2);border-radius:6px;padding:1px 8px;font-size:12px}
details summary{cursor:pointer;color:var(--ink-2);margin:14px 0 10px;font-size:13px}
.toolbar{display:flex;gap:12px;align-items:center;margin-bottom:10px}
#filter{flex:1;max-width:420px;font:inherit;padding:8px 12px;border-radius:9px;border:1px solid var(--border);background:var(--surface);color:var(--ink)}
#filter:focus{outline:2px solid var(--accent);outline-offset:-1px}
.empty{color:var(--ink-2);background:var(--surface);border:1px dashed var(--axis);border-radius:12px;padding:16px 18px;margin:0}
.notes ul{color:var(--ink-2);padding-left:18px;max-width:860px}.notes li{margin:4px 0}
#tip{position:fixed;z-index:10;pointer-events:none;background:var(--ink);color:var(--page);font-size:12px;line-height:1.45;
padding:8px 10px;border-radius:8px;max-width:380px;white-space:pre-line;box-shadow:0 6px 24px rgba(0,0,0,.18)}
@media (max-width:640px){main{padding:24px 16px 60px}h1{font-size:22px}.kv{font-size:22px}}
@media print{.figure svg{min-width:0}#filter,.toolbar{display:none}}
</style></head>
<body><main>{{BODY}}</main><div id="tip" hidden></div>
<script>
(()=>{
const tip=document.getElementById('tip');
document.addEventListener('mouseover',e=>{const t=e.target.closest('[data-tip]');if(!t||!t.dataset.tip){tip.hidden=true;return}tip.textContent=t.dataset.tip;tip.hidden=false});
document.addEventListener('mousemove',e=>{if(tip.hidden)return;const r=tip.getBoundingClientRect();let x=e.clientX+14,y=e.clientY+16;
if(x+r.width>innerWidth-8)x=e.clientX-r.width-14;if(y+r.height>innerHeight-8)y=e.clientY-r.height-12;tip.style.left=x+'px';tip.style.top=y+'px'});
document.addEventListener('scroll',()=>tip.hidden=true,{passive:true});
document.querySelectorAll('svg.flows').forEach(svg=>{svg.querySelectorAll('.fnode').forEach(n=>{
 n.addEventListener('mouseenter',()=>{const k=n.dataset.k;svg.classList.add('focus');svg.querySelectorAll('.edge').forEach(p=>p.classList.toggle('on',p.dataset.a===k||p.dataset.b===k))});
 n.addEventListener('mouseleave',()=>svg.classList.remove('focus'));})});
document.querySelectorAll('table.sortable').forEach(tbl=>{tbl.querySelectorAll('th').forEach((th,i)=>th.addEventListener('click',()=>{
 const dir=th.classList.contains('asc')?-1:1;tbl.querySelectorAll('th').forEach(h=>h.classList.remove('asc','desc'));th.classList.add(dir>0?'asc':'desc');
 const body=tbl.tBodies[0],rows=[...body.rows];const val=r=>{const c=r.cells[i];if(!c)return'';const s=c.dataset.sort??c.textContent.trim();const n=parseFloat(s);return s!==''&&!isNaN(n)&&/^-?[\\d.]+$/.test(s)?n:s.toLowerCase()};
 rows.sort((a,b)=>{const x=val(a),y=val(b);return (x>y?1:x<y?-1:0)*dir});rows.forEach(r=>body.appendChild(r));}))});
const f=document.getElementById('filter'),inv=document.getElementById('inventory'),cnt=document.getElementById('count');
if(f&&inv){const upd=()=>{const q=f.value.toLowerCase().trim();let n=0;[...inv.tBodies[0].rows].forEach(r=>{const show=!q||r.textContent.toLowerCase().includes(q);r.hidden=!show;n+=show});cnt.textContent=n+' of '+inv.tBodies[0].rows.length+' hosts'};f.addEventListener('input',upd);upd()}
})();
</script></body></html>
""".replace("ZONES_LIGHT", zone_css(0)).replace("ZONES_DARK", zone_css(1))


# ──────────────────────────── terminal summary ─────────────────────────────


def print_summary(scan: Scan, paths: list):
    if QUIET:
        for p in paths:
            print(p)
        return
    colors = {z[0]: z[4][1] for z in ZONES}
    t = Table(box=box.SIMPLE_HEAD, header_style="grey62", show_edge=False, pad_edge=False, expand=False)
    for col, width, floor in (("IP", None, 18), ("Name", 22, 8), ("Vendor", 18, 8), ("Role", None, 14), ("Open ports", 40, 8)):
        t.add_column(col, no_wrap=True, overflow="ellipsis", max_width=width, min_width=floor)
    for h in scan.hosts:
        ip = Text(h.ip, style="bold" if h.is_self or h.is_gateway else "")
        if h.is_self:
            ip.append(" you", style=ACCENT)
        if h.is_gateway:
            ip.append(" gw", style=ACCENT)
        role = Text("● ", style=colors[h.zone]).append(ROLES[h.role][1])
        ports = " ".join(f"{p.port}" + ("/u" if p.proto == "udp" else "") for p in h.ports[:12]) + (" …" if len(h.ports) > 12 else "")
        t.add_row(ip, h.name.split(".")[0] if h.name else Text("—", style="grey42"), h.vendor or Text("—", style="grey42"), role, Text(ports, style="grey70"))
    console.print()
    console.print(t)
    zc = Counter(h.zone for h in scan.hosts)
    console.print(Text("  Zones", style="bold"))
    console.print(Padding(Columns([Text("● ", style=z[4][1]).append(z[1] + " ").append(str(zc[z[0]]), style="grey62")
                                   for z in ZONES if zc.get(z[0])], padding=(0, 3)), (0, 0, 0, 2)))
    ep = Endpoints(scan)
    rows = aggregate_flows(scan, ep)
    console.print(Text("  Flows", style="bold"))
    console.print(f"  [grey70]{len(rows)} conversations · {len(zone_rules(rows, ep))} cross-zone rules[/]"
                  + ("" if scan.capture_s else "  [grey50](run with sudo for passive capture)[/]"))
    console.print(Text("  Report", style="bold"))
    for p in paths:
        console.print(f"  [{ACCENT}]{p}[/]")
    console.print()


# ─────────────────────────────────── CLI ───────────────────────────────────


def main(argv=None):
    global QUIET
    ap = argparse.ArgumentParser(
        prog="lanmap", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Map the local network and write an HTML report: topology, address map, open ports, data flows and a VLAN plan.",
        epilog="examples:\n"
               "  lanmap                         scan every attached subnet\n"
               "  sudo lanmap --capture 300      ...and listen to traffic for 5 minutes\n"
               "  lanmap -t 10.0.20.0/24 -p 1-1024,3389,8080\n"
               "  lanmap --demo --open           render a sample report\n"
               "  lanmap --from-json scan.json   re-render a saved scan")
    ap.add_argument("-t", "--target", action="append", metavar="CIDR", help="subnet to scan (repeatable; default: attached subnets)")
    ap.add_argument("-i", "--interface", action="append", metavar="IFACE", help="only use this interface (repeatable)")
    ap.add_argument("-p", "--ports", default="top", help="'top' (%d common ports, default), 'all', or a list like 22,80,8000-8100" % len(TOP_TCP))
    ap.add_argument("-c", "--capture", type=int, default=None, metavar="SEC", help="passive capture duration in seconds (root; default 30 when root, else off)")
    ap.add_argument("-o", "--output", metavar="FILE", help="HTML report path (default: lanmap-<timestamp>.html)")
    ap.add_argument("--no-json", action="store_true", help="don't write the JSON scan file next to the report")
    ap.add_argument("--timeout", type=float, default=1.0, help="connect/ping timeout in seconds (default 1.0)")
    ap.add_argument("--concurrency", type=int, default=512, help="parallel TCP connects (default 512)")
    ap.add_argument("--ping-concurrency", type=int, default=96, help="parallel pings (default 96)")
    ap.add_argument("--no-udp", action="store_true", help="skip NetBIOS and SNMP probes")
    ap.add_argument("--no-banners", action="store_true", help="skip service banner grabbing")
    ap.add_argument("--no-trace", action="store_true", help="skip traceroute to the internet")
    ap.add_argument("--include-virtual", action="store_true", help="include docker/bridge/vpn interfaces")
    ap.add_argument("--allow-public", action="store_true", help="permit non-RFC1918 targets you are authorised to scan")
    ap.add_argument("--max-hosts", type=int, default=4096, help="refuse targets larger than this (default 4096)")
    ap.add_argument("--open", action="store_true", help="open the report in a browser when done")
    ap.add_argument("--demo", action="store_true", help="generate a report from synthetic data (no scanning)")
    ap.add_argument("--from-json", metavar="FILE", help="render a report from a saved JSON scan")
    ap.add_argument("-q", "--quiet", action="store_true", help="no progress output; print report paths only")
    ap.add_argument("-V", "--version", action="version", version=f"lanmap {__version__}")
    opts = ap.parse_args(argv)
    QUIET = opts.quiet

    if not QUIET:
        console.print()
        console.print(f"  [bold]lanmap[/] [grey50]{__version__}[/]  [grey42]·[/]  [grey62]{socket.gethostname()}[/]"
                      + ("  [grey42]·[/]  [grey62]root[/]" if is_root() else ""))
        console.print()

    try:
        if opts.demo:
            scan = demo_scan()
            info("demo mode: synthetic data, nothing was scanned")
        elif opts.from_json:
            scan = Scan.from_json(Path(opts.from_json).read_text(encoding="utf-8"))
            finalise(scan)
        else:
            if not sys.platform.startswith("linux"):
                raise SystemExit("Live scanning needs Linux (iproute2). Use --demo or --from-json elsewhere.")
            if not shutil.which("ip"):
                raise SystemExit("The 'ip' command (iproute2) is required.")
            if opts.capture is None:
                opts.capture = 30 if is_root() else 0
            scan = asyncio.run(do_scan(opts))
    except KeyboardInterrupt:
        console.print("\n  [yellow]interrupted[/]")
        return 130

    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    out = Path(opts.output or f"lanmap-{'demo-' if opts.demo else ''}{stamp}.html")
    out.write_text(build_report(scan), encoding="utf-8")
    paths = [str(out.resolve())]
    if not opts.no_json and not opts.from_json:
        jpath = out.with_suffix(".json")
        jpath.write_text(scan.to_json(), encoding="utf-8")
        paths.append(str(jpath.resolve()))
    print_summary(scan, paths)
    if opts.open:
        webbrowser.open(out.resolve().as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())
