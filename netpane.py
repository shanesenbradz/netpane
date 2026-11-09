#!/usr/bin/env python3
"""
NetPane: a single pane of glass for Linux network troubleshooting.

Linux:       sudo python3 netpane.py
Windows:     NetPane.exe   (or: python netpane.py, after pip install psutil)
Then open:   http://127.0.0.1:8765   (opens automatically)

On Linux only the standard library is needed; root unlocks arping, tcpdump,
nethogs and process names on every socket. On Windows it uses psutil plus the
built-in tools (ping, tracert, netsh, PowerShell). Every external tool is used
when present and skipped when not.
"""

import argparse
import atexit
import base64
import collections
import concurrent.futures as cf
import datetime as dt
import importlib.util
import ipaddress
import json
import os
import platform as pyplatform
import random
import re
import shlex
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    import psutil
except ImportError:  # optional on Linux, bundled in the Windows exe
    psutil = None

VERSION = "1.5.0"
IS_WIN = os.name == "nt"
PLATFORM = "windows" if IS_WIN else "linux"


def _is_admin():
    if IS_WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


IS_ROOT = _is_admin()
ENV = dict(os.environ, LC_ALL="C", LANG="C")
STATE = {}
STATE_LOCK = threading.Lock()
TRAFFIC = collections.defaultdict(lambda: collections.deque(maxlen=120))
ALLOWED_HOSTS = set()
ALLOW_ANY_HOST = False


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def remember(key, value):
    with STATE_LOCK:
        STATE[key] = {"at": now(), "data": value}
    return value


WIN_TOOL_DIRS = [os.path.join(os.environ.get(v, ""), d) for v, d in
                 (("ProgramFiles", "Wireshark"), ("ProgramFiles", "Nmap"), ("ProgramFiles(x86)", "Nmap"),
                  ("ProgramFiles", "iperf3"), ("ProgramFiles", "Sysinternals"))]


def which(binary):
    found = shutil.which(binary)
    if found or not IS_WIN:
        return found
    for d in WIN_TOOL_DIRS:
        for ext in (".exe", ""):
            cand = os.path.join(d, binary + ext)
            if os.path.isfile(cand):
                return cand
    return None


def have(binary):
    return which(binary) is not None


def run(cmd, timeout=15, encoding=None):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    path = which(cmd[0]) if cmd else None
    if not path:
        return {"ok": False, "rc": 127, "out": "", "err": f"{cmd[0] if cmd else '?'} is not installed"}
    extra = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)} if IS_WIN else {}
    try:
        p = subprocess.run([path] + list(cmd[1:]), capture_output=True, text=True, timeout=timeout,
                           env=ENV, stdin=subprocess.DEVNULL, errors="replace",
                           encoding=encoding or ("oem" if IS_WIN else "utf-8"), **extra)
        return {"ok": p.returncode == 0, "rc": p.returncode, "out": p.stdout, "err": p.stderr}
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return {"ok": False, "rc": 124, "out": out, "err": f"stopped after {timeout}s"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "rc": 1, "out": "", "err": str(e)}


def run_json(cmd, timeout=15):
    r = run(cmd, timeout)
    try:
        return json.loads(r["out"]) if r["out"].strip() else None
    except ValueError:
        return None


def read(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


# --------------------------------------------------------------------------
# tool inventory (the 30 tools plus a couple of name helpers)
# --------------------------------------------------------------------------
TOOLS_LINUX = [
    ("ping", "iputils-ping", "Connectivity", "Reachability and round-trip time"),
    ("traceroute", "traceroute", "Connectivity", "Hop-by-hop path"),
    ("tracepath", "iputils-tracepath", "Connectivity", "Path and MTU discovery, no root needed"),
    ("mtr", "mtr-tiny", "Connectivity", "Ping and traceroute combined"),
    ("hping3", "hping3", "Connectivity", "Custom TCP/UDP/ICMP packets"),
    ("fping", "fping", "Connectivity", "Ping many hosts at once"),
    ("ip", "iproute2", "Interfaces", "Interfaces, addresses, routes, neighbours"),
    ("ifconfig", "net-tools", "Interfaces", "Legacy interface tool"),
    ("ethtool", "ethtool", "Interfaces", "NIC speed, duplex, driver, link"),
    ("iw", "iw", "Interfaces", "Wireless interface details"),
    ("iwconfig", "wireless-tools", "Interfaces", "Legacy wireless tool"),
    ("nmcli", "network-manager", "Interfaces", "NetworkManager CLI"),
    ("lspci", "pciutils", "Interfaces", "Physical network hardware"),
    ("lshw", "lshw", "Interfaces", "Hardware listing"),
    ("route", "net-tools", "Routing & ARP", "Legacy routing table"),
    ("arp", "net-tools", "Routing & ARP", "Legacy ARP table"),
    ("arping", "arping", "Routing & ARP", "Layer 2 ping"),
    ("ss", "iproute2", "Sockets", "Open sockets and ports"),
    ("netstat", "net-tools", "Sockets", "Legacy connections and stats"),
    ("lsof", "lsof", "Sockets", "Which process owns which connection"),
    ("nc", "netcat-openbsd", "Sockets", "Raw TCP/UDP and port checks"),
    ("dig", "dnsutils", "DNS", "Detailed DNS queries"),
    ("nslookup", "dnsutils", "DNS", "Simple DNS lookup"),
    ("host", "dnsutils", "DNS", "Readable DNS lookup"),
    ("whois", "whois", "DNS", "Domain and IP registration"),
    ("tcpdump", "tcpdump", "Capture", "Packet capture"),
    ("tshark", "tshark", "Capture", "Wireshark on the command line"),
    ("ngrep", "ngrep", "Capture", "grep for network traffic"),
    ("nmap", "nmap", "Scanning", "Hosts, ports and services"),
    ("iperf3", "iperf3", "Bandwidth", "Throughput between two hosts"),
    ("iftop", "iftop", "Bandwidth", "Bandwidth per connection"),
    ("nload", "nload", "Bandwidth", "Bandwidth per interface"),
    ("nethogs", "nethogs", "Bandwidth", "Bandwidth per process"),
    ("vnstat", "vnstat", "Bandwidth", "Traffic history"),
]
PRESETS_LINUX = {
    "ping": ["-c 4 {gw}", "-c 4 1.1.1.1", "-c 4 google.com"], "traceroute": ["-n 1.1.1.1"], "tracepath": ["-n 1.1.1.1"],
    "mtr": ["-n 1.1.1.1", "-n google.com"], "hping3": ["-S -p 443 -c 3 1.1.1.1"],
    "fping": ["-a -g {net}", "-c 3 {gw} 1.1.1.1 8.8.8.8"], "ip": ["addr", "route", "neigh", "-s link", "rule"],
    "ifconfig": ["-a"], "ethtool": ["{dev}", "-i {dev}", "-S {dev}"], "iw": ["dev", "dev {dev} link"], "iwconfig": [""],
    "nmcli": ["device", "connection show", "device wifi list", "general"], "lspci": ["-nn"],
    "lshw": ["-class network -short"], "route": ["-n"], "arp": ["-n"], "arping": ["-c 3 -I {dev} {gw}"],
    "ss": ["-tulpn", "-tunap", "-s"], "netstat": ["-tulpn", "-i", "-rn"], "lsof": ["-i -P -n"],
    "nc": ["-zv -w 3 {gw} 80", "-zv -w 3 google.com 443"],
    "dig": ["google.com", "+trace google.com", "-x 8.8.8.8", "MX gmail.com"], "nslookup": ["google.com"],
    "host": ["google.com"], "whois": ["8.8.8.8", "google.com"],
    "tcpdump": ["-i {dev} -c 30", "-i {dev} -c 30 port 53", "-i {dev} -c 20 arp", "-i {dev} -c 30 icmp"],
    "tshark": ["-i {dev} -c 30"], "ngrep": ["-d {dev} -q -n 20 GET"], "nmap": ["-sn {net}", "-F {gw}", "-sV -F {gw}"],
    "iperf3": ["-c <server> -t 5", "-c <server> -R -t 5", "-s"], "iftop": ["-i {dev}"], "nethogs": ["{dev}"],
    "nload": [""], "vnstat": ["", "-d", "-h", "-m"],
}
TOOLS_WIN = [
    ("ping", "built in", "Connectivity", "Reachability and round-trip time"),
    ("tracert", "built in", "Connectivity", "Hop-by-hop path"),
    ("pathping", "built in", "Connectivity", "Trace plus per-hop loss statistics"),
    ("curl", "built in", "Connectivity", "HTTP and HTTPS requests"),
    ("ipconfig", "built in", "Interfaces", "Addresses, DHCP and DNS settings"),
    ("getmac", "built in", "Interfaces", "Hardware addresses"),
    ("netsh", "built in", "Interfaces", "Wi-Fi, interfaces and firewall settings"),
    ("hostname", "built in", "Interfaces", "This computer's name"),
    ("route", "built in", "Routing & ARP", "Routing table"),
    ("arp", "built in", "Routing & ARP", "ARP table (IP to MAC)"),
    ("netstat", "built in", "Sockets", "Connections, ports and interface stats"),
    ("nslookup", "built in", "DNS", "DNS lookups"),
    ("nbtstat", "built in", "DNS", "NetBIOS names"),
    ("whois", "Sysinternals", "DNS", "Domain and IP registration"),
    ("tshark", "Wireshark", "Capture", "Wireshark on the command line"),
    ("nmap", "Nmap", "Scanning", "Hosts, ports and services"),
    ("iperf3", "iperf3", "Bandwidth", "Throughput between two hosts"),
]
PRESETS_WIN = {
    "ping": ["-n 4 {gw}", "-n 4 1.1.1.1", "-n 4 google.com", "-f -l 1472 -n 2 1.1.1.1"],
    "tracert": ["-d 1.1.1.1", "-d google.com"], "pathping": ["-n 1.1.1.1"],
    "curl": ["-sI https://www.google.com", "-s https://api.ipify.org"], "ipconfig": ["/all", "/displaydns"],
    "getmac": ["/v"], "hostname": [""],
    "netsh": ["wlan show interfaces", "wlan show networks mode=bssid", "interface ipv4 show subinterfaces",
              "advfirewall show allprofiles state"],
    "route": ["print -4"], "arp": ["-a"], "netstat": ["-ano", "-e", "-rn", "-s"],
    "nslookup": ["google.com", "google.com 1.1.1.1", "-type=MX gmail.com"], "nbtstat": ["-A {gw}", "-n"],
    "whois": ["8.8.8.8"], "tshark": ["-D", "-i 1 -c 30"], "nmap": ["-sn {net}", "-F {gw}", "-sV -F {gw}"],
    "iperf3": ["-c <server> -t 5", "-c <server> -R -t 5", "-s"],
}
WINGET = {"nmap": "Insecure.Nmap", "tshark": "WiresharkFoundation.Wireshark"}
TOOLS = TOOLS_WIN if IS_WIN else TOOLS_LINUX
PRESETS = PRESETS_WIN if IS_WIN else PRESETS_LINUX


def tool_inventory():
    tools = [{"cmd": c, "package": p, "category": cat, "desc": d, "installed": have(c), "path": which(c) or "",
              "presets": PRESETS.get(c, [])} for c, p, cat, d in TOOLS]
    libs = [{"name": n, "installed": importlib.util.find_spec(m) is not None}
            for n, m in (("scapy", "scapy"), ("psutil", "psutil"))]
    missing = [t for t in tools if not t["installed"]]
    if IS_WIN:
        cmds = [f"winget install -e --id {WINGET[t['cmd']]}" for t in missing if t["cmd"] in WINGET]
        install = "; ".join(cmds)
        hint = "Add the optional extras from PowerShell (the Nmap installer also adds Npcap):"
    else:
        pkgs = sorted({t["package"] for t in missing})
        install = ("sudo apt install -y " + " ".join(pkgs)) if pkgs else ""
        hint = "Install the missing ones on Debian or Ubuntu:"
    return {"tools": tools, "libs": libs, "installed": sum(t["installed"] for t in tools),
            "install_cmd": install, "install_hint": hint, "platform": PLATFORM}


# --------------------------------------------------------------------------
# MAC vendor lookup (uses OUI files that nmap / ieee-data / hwdata ship)
# --------------------------------------------------------------------------
_OUI = None
_OUI_LOCK = threading.Lock()


def oui_db():
    global _OUI
    with _OUI_LOCK:
        if _OUI is not None:
            return _OUI
        db = {}
        p = "/usr/share/nmap/nmap-mac-prefixes"
        if os.path.exists(p):
            with open(p, errors="ignore") as f:
                for line in f:
                    if line.startswith("#"):
                        continue
                    k, _, v = line.strip().partition(" ")
                    if len(k) == 6:
                        db[k.upper()] = v.strip()
        for p in ("/usr/share/ieee-data/oui.txt", "/usr/share/hwdata/oui.txt",
                  "/var/lib/ieee-data/oui.txt", "/usr/share/misc/oui.txt"):
            if os.path.exists(p):
                with open(p, errors="ignore") as f:
                    for line in f:
                        m = re.match(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$",
                                     line.strip())
                        if m:
                            db.setdefault((m.group(1) + m.group(2) + m.group(3)).upper(), m.group(4).strip())
        _OUI = db
        return db


def vendor(mac):
    if not mac:
        return ""
    h = mac.replace(":", "").replace("-", "").upper()
    if len(h) < 6 or not re.match(r"^[0-9A-F]+$", h):
        return ""
    if int(h[1], 16) & 2:
        return "Private / randomised MAC"
    return oui_db().get(h[:6], "")



# --------------------------------------------------------------------------
# pure-Python DNS, mDNS and NetBIOS lookups (same on Linux and Windows)
# --------------------------------------------------------------------------
def _dns_name(msg, off, depth=0):
    labels, jumped, end = [], False, off
    while True:
        if off >= len(msg):
            raise ValueError("truncated")
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            depth += 1
            if depth > 20:
                raise ValueError("pointer loop")
            if not jumped:
                end = off + 2
            jumped = True
            off = ((ln & 0x3F) << 8) | msg[off + 1]
            continue
        labels.append(msg[off + 1:off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(labels), (end if jumped else off)


def _qname(name):
    out = b""
    for part in name.rstrip(".").split("."):
        if part:
            p = part.encode("ascii", "ignore")[:63]
            out += bytes([len(p)]) + p
    return out + b"\x00"


DNS_RCODES = {1: "malformed query (FORMERR)", 2: "server failure (SERVFAIL)",
              3: "name does not exist (NXDOMAIN)", 4: "not implemented", 5: "refused"}


def dns_query(server, name, qtype=1, port=53, timeout=2.0, raw_name=None):
    """Send one UDP DNS-style query and parse the answers. Used for DNS (53), mDNS (5353) and NetBIOS (137)."""
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100 if port == 53 else 0
    pkt = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0) + (raw_name or _qname(name)) + struct.pack(">HH", qtype, 1)
    host = server.split("%")[0]
    t0 = time.time()
    ms = lambda: round((time.time() - t0) * 1000)  # noqa: E731
    try:
        s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as e:
        return {"ok": False, "err": str(e), "ms": 0, "answers": []}
    try:
        s.sendto(pkt, (host, port))
        while True:
            left = timeout - (time.time() - t0)
            if left <= 0:
                raise socket.timeout()
            s.settimeout(left)
            data, _ = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid:
                break
    except socket.timeout:
        return {"ok": False, "err": "timed out", "ms": ms(), "answers": []}
    except OSError as e:
        return {"ok": False, "err": str(e), "ms": ms(), "answers": []}
    finally:
        s.close()
    took = ms()
    try:
        rflags, qd, an = struct.unpack(">HHH", data[2:8])
        off = 12
        for _ in range(qd):
            _, off = _dns_name(data, off)
            off += 4
        answers = []
        for _ in range(an):
            _, off = _dns_name(data, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                answers.append(socket.inet_ntoa(rdata))
            elif rtype == 12:
                answers.append(_dns_name(data, off)[0])
            elif rtype == 33 and qtype == 33:  # NetBIOS node status
                answers.append(rdata)
            off += rdlen
    except (ValueError, struct.error, IndexError):
        return {"ok": False, "err": "malformed reply", "ms": took, "answers": []}
    rcode = rflags & 0xF
    ok = rcode == 0 and bool(answers)
    err = "" if ok else (DNS_RCODES.get(rcode, f"error code {rcode}") if rcode else "no answer")
    return {"ok": ok, "rcode": rcode, "err": err, "answers": answers, "ms": took}


def mdns_name(ip):
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    r = dns_query(ip, rev, 12, port=5353, timeout=1.0)
    for a in r["answers"]:
        if isinstance(a, str) and a:
            return a.rstrip(".")
    return ""


def nbns_name(ip):
    enc = "".join(chr(65 + (b >> 4)) + chr(65 + (b & 15)) for b in b"*" + b"\x00" * 15).encode()
    r = dns_query(ip, "", 0x21, port=137, timeout=1.0, raw_name=bytes([32]) + enc + b"\x00")
    for rd in r["answers"]:
        if not isinstance(rd, bytes) or not rd:
            continue
        for i in range(rd[0]):
            e = rd[1 + i * 18:1 + (i + 1) * 18]
            if len(e) < 18:
                break
            nm = e[:15].decode("ascii", "replace").strip()
            if e[15] == 0 and not struct.unpack(">H", e[16:18])[0] & 0x8000 and nm:
                return nm
    return ""


# --------------------------------------------------------------------------
# Windows platform layer (psutil + PowerShell + built-in tools)
# --------------------------------------------------------------------------
def W(linux_text, windows_text):
    return windows_text if IS_WIN else linux_text


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def powershell(script, timeout=30):
    full = "$ErrorActionPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + script
    enc = base64.b64encode(full.encode("utf-16-le")).decode()
    r = run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc],
            timeout, encoding="utf-8")
    try:
        return json.loads(r["out"]) if r["out"].strip() else None
    except ValueError:
        return None


PS_SNAPSHOT = (
    "$o=[ordered]@{};"
    "$o.adapters=@(Get-NetAdapter | Select-Object Name,InterfaceDescription,MacAddress,LinkSpeed,HardwareInterface,"
    "@{n='Status';e={[string]$_.Status}},@{n='Media';e={[string]$_.PhysicalMediaType}});"
    "$o.routes=@(Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,InterfaceMetric);"
    "$o.dns=@(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses} | Select-Object InterfaceAlias,ServerAddresses);"
    "$o.suffix=@((Get-DnsClientGlobalSetting).SuffixSearchList);"
    "$o | ConvertTo-Json -Depth 4 -Compress"
)
PS_NEIGH = ("@(Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,"
            "@{n='State';e={[string]$_.State}}) | ConvertTo-Json -Compress")
_SNAP = {"t": 0, "d": None}
_SNAP_LOCK = threading.Lock()


def win_snapshot(force=False):
    with _SNAP_LOCK:
        if not force and _SNAP["d"] and time.time() - _SNAP["t"] < 5:
            return _SNAP["d"]
        raw = powershell(PS_SNAPSHOT) or {}
        d = {k: as_list(raw.get(k)) for k in ("adapters", "routes", "dns", "suffix")}
        _SNAP.update(t=time.time(), d=d)
        return d


def neigh_table(dev=None, ip=None):
    """Neighbour (ARP) table in the same shape as `ip -j neigh` output."""
    if not IS_WIN:
        return run_json(["ip", "-j", "neigh", "show"] + (["dev", dev] if dev else []) + ([ip] if ip else [])) or []
    rows = as_list(powershell(PS_NEIGH))
    if not rows:  # fall back to arp -a
        for line in run(["arp", "-a"], 10)["out"].splitlines():
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\S+)", line)
            if m:
                rows.append({"IPAddress": m.group(1), "LinkLayerAddress": m.group(2), "State": "Reachable"})
    out = []
    for r in rows:
        ipa = str(r.get("IPAddress") or "")
        if ":" in ipa or not ipa or (dev and r.get("InterfaceAlias") not in (None, dev)) or (ip and ipa != ip):
            continue
        try:
            a = ipaddress.ip_address(ipa)
            if a.is_multicast or ipa.endswith(".255"):
                continue
        except ValueError:
            continue
        mac = str(r.get("LinkLayerAddress") or "").replace("-", ":").lower()
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            mac = ""
        st = str(r.get("State") or "").upper()
        out.append({"dst": ipa, "lladdr": mac, "state": ["FAILED" if st == "UNREACHABLE" else st]})
    return out


def _netsh_blocks(text):
    blocks, cur = [], {}
    for line in text.splitlines():
        if ":" not in line:
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        if k == "name" and "name" in cur:
            blocks.append(cur)
            cur = {}
        cur[k] = v.strip()
    if cur:
        blocks.append(cur)
    return blocks


def wifi_links_win():
    out = {}
    for b in _netsh_blocks(run(["netsh", "wlan", "show", "interfaces"], 10)["out"]):
        if "name" not in b:
            continue
        info = {"ssid": b.get("ssid", ""), "bssid": b.get("ap bssid") or b.get("bssid", "")}
        m = re.match(r"(\d+)", b.get("signal", ""))
        if m:
            pct = int(m.group(1))
            info.update(signal_pct=pct, signal=round(pct / 2 - 100))
        if b.get("band"):
            info["freq"] = b["band"]
        if b.get("channel"):
            info["channel"] = b["channel"]
        rate = b.get("receive rate (mbps)") or b.get("transmit rate (mbps)")
        if rate:
            info["bitrate"] = f"{rate} Mbit/s"
        info["connected"] = bool(info["ssid"])
        out[b["name"]] = info
    return out


def interfaces_win():
    if psutil is None:
        return []
    ad = {a.get("Name"): a for a in win_snapshot()["adapters"]}
    addrs, stats, io = psutil.net_if_addrs(), psutil.net_if_stats(), psutil.net_io_counters(pernic=True)
    wl = None
    out = []
    for name, al in addrs.items():
        a, st, c = ad.get(name, {}), stats.get(name), io.get(name)
        mac, v4, v6 = "", [], []
        for x in al:
            if x.family == psutil.AF_LINK:
                mac = x.address.replace("-", ":").lower()
            elif x.family == socket.AF_INET:
                try:
                    pl = ipaddress.ip_network(f"0.0.0.0/{x.netmask}").prefixlen if x.netmask else 32
                except ValueError:
                    pl = 24
                v4.append(f"{x.address}/{pl}")
            elif x.family == socket.AF_INET6:
                v6.append(x.address.split("%")[0])
        lo = name.lower().startswith("loopback") or any(v.startswith("127.") for v in v4)
        up = bool(st and st.isup)
        desc = str(a.get("InterfaceDescription") or "")
        wireless = "802.11" in str(a.get("Media") or "") or bool(re.search(r"wi-?fi|wireless|wlan|802\.11", desc + " " + name, re.I))
        duplex = {psutil.NIC_DUPLEX_FULL: "full", psutil.NIC_DUPLEX_HALF: "half"}.get(getattr(st, "duplex", None))
        item = {
            "name": name, "state": "UP" if up else "DOWN", "mac": mac, "mtu": st.mtu if st else None,
            "flags": ["LOOPBACK"] if lo else [], "carrier": None if lo else ("1" if up else "0"),
            "speed": (st.speed or None) if st else None, "duplex": duplex, "driver": desc or None,
            "wireless": wireless, "virtual": a.get("HardwareInterface") is False or (not a and not lo),
            "loopback": lo, "ipv4": v4, "ipv6": v6,
            "rx_bytes": c.bytes_recv if c else None, "tx_bytes": c.bytes_sent if c else None,
            "rx_errors": c.errin if c else 0, "tx_errors": c.errout if c else 0,
            "rx_dropped": c.dropin if c else 0, "tx_dropped": c.dropout if c else 0,
        }
        item["vendor"] = "" if lo else vendor(mac)
        if wireless:
            if wl is None:
                wl = wifi_links_win()
            item["wifi"] = wl.get(name, {"connected": False})
        out.append(item)
    return out


def routes_win():
    r4, gws = [], []
    for r in win_snapshot()["routes"]:
        dst, nh = str(r.get("DestinationPrefix") or ""), str(r.get("NextHop") or "0.0.0.0")
        try:
            net = ipaddress.ip_network(dst, strict=False)
        except ValueError:
            continue
        if net.is_multicast or net.is_loopback or net.prefixlen == 32:
            continue
        metric = int(r.get("RouteMetric") or 0) + int(r.get("InterfaceMetric") or 0)
        row = {"dst": "default" if dst == "0.0.0.0/0" else dst, "dev": r.get("InterfaceAlias"), "metric": metric}
        if nh != "0.0.0.0":
            row["gateway"] = nh
        r4.append(row)
        if row["dst"] == "default" and row.get("gateway"):
            gws.append({"gateway": nh, "dev": row["dev"], "metric": metric, "proto": ""})
    gws.sort(key=lambda g: g["metric"])
    r4.sort(key=lambda x: (x["dst"] != "default", x["metric"]))
    return {"ipv4": r4, "ipv6": [], "gateways": gws}


def dns_info_win():
    snap = win_snapshot()
    gws = routes_win()["gateways"]
    pdev = gws[0]["dev"] if gws else None
    rows = snap["dns"]
    mine = [r for r in rows if r.get("InterfaceAlias") == pdev] or rows
    servers = []
    for r in mine:
        for s in as_list(r.get("ServerAddresses")):
            if s and s not in servers and not str(s).lower().startswith("fec0"):
                servers.append(s)
    return {"resolv_conf": servers, "upstream": [], "search": [s for s in snap["suffix"] if s], "stub": False}


def extras_win():
    lines = [f"{a.get('Name')}: {a.get('InterfaceDescription')} ({a.get('LinkSpeed') or '?'}, {a.get('Status') or '?'})"
             for a in win_snapshot()["adapters"]]
    return {"pci": lines} if lines else {}


def wifi_scan_win():
    r = run(["netsh", "wlan", "show", "networks", "mode=bssid"], 15)
    nets, cur = [], None
    for line in r["out"].splitlines():
        s = line.strip()
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", s)
        if m:
            cur = {"ssid": m.group(1), "signal": 0, "chan": "", "security": "open", "inuse": False}
            nets.append(cur)
        elif cur and ":" in s:
            k, _, v = s.partition(":")
            k, v = k.strip().lower(), v.strip()
            if k.startswith("authentication"):
                cur["security"] = v
            elif k == "signal":
                m = re.match(r"(\d+)", v)
                if m:
                    cur["signal"] = max(cur["signal"], int(m.group(1)))
            elif k == "channel" and not cur["chan"]:
                cur["chan"] = v
    connected = {i.get("ssid") for i in wifi_links_win().values() if i.get("ssid")}
    for n in nets:
        n["inuse"] = n["ssid"] in connected
    nets.sort(key=lambda n: -n["signal"])
    note = "" if nets else (r["out"].strip() or r["err"].strip() or "No Wi-Fi networks found.")[:400]
    return {"networks": nets, "note": note}


def win_sweep(net):
    hosts = [str(h) for h in net.hosts()]
    # A UDP packet to each address makes Windows resolve its MAC, so devices that drop ping still show up.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for h in hosts:
            try:
                s.sendto(b"\x00", (h, 9))
            except OSError:
                pass
        s.close()
    except OSError:
        pass
    with cf.ThreadPoolExecutor(48) as ex:
        res = list(ex.map(lambda h: run(["ping", "-n", "1", "-w", "700", h], 6), hosts))
    return {h for h, r in zip(hosts, res) if "TTL=" in r["out"].upper()}


def parse_tracert(out):
    hops = []
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*\S)\s*$", line)
        if not m:
            continue
        rest = m.group(2)
        vals = [0.5 if lt else float(v) for lt, v in re.findall(r"(<?)\s*(\d+)\s*ms", rest)]
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", rest)
        hops.append({"hop": int(m.group(1)), "host": ips[-1] if ips else "???",
                     "loss": round(100 * (3 - min(len(vals), 3)) / 3),
                     "avg": round(sum(vals) / len(vals), 1) if vals else None,
                     "best": min(vals) if vals else None, "worst": max(vals) if vals else None})
    return hops


def parse_ping_win(out, sent):
    vals = [0.5 if lt == "<" else float(v) for lt, v in re.findall(r"([=<])\s*(\d+)\s*ms\s+TTL=", out, re.I)]
    sent = max(sent, 1)
    p = {"loss": round(100.0 * (sent - min(len(vals), sent)) / sent, 1), "min": None, "avg": None, "max": None, "mdev": None}
    if vals:
        p.update(min=min(vals), avg=round(sum(vals) / len(vals), 2), max=max(vals),
                 mdev=round(statistics.pstdev(vals), 2))
    return p


SOCK_STATES = {"ESTABLISHED": "ESTAB", "LISTEN": "LISTEN", "NONE": "UNCONN", "TIME_WAIT": "TIME-WAIT",
               "CLOSE_WAIT": "CLOSE-WAIT", "SYN_SENT": "SYN-SENT", "SYN_RECV": "SYN-RECV", "FIN_WAIT1": "FIN-WAIT-1",
               "FIN_WAIT2": "FIN-WAIT-2", "LAST_ACK": "LAST-ACK", "CLOSING": "CLOSING", "CLOSE": "CLOSED"}


def win_socket_rows():
    if psutil is None:
        return []
    names = {}

    def pname(pid):
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name()
            except Exception:  # noqa: BLE001
                names[pid] = ""
        return names[pid]

    def fmt(a):
        if not a:
            return "*:*"
        return f"[{a.ip}]:{a.port}" if ":" in a.ip else f"{a.ip}:{a.port}"
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:  # noqa: BLE001
        conns = []
    return [{"proto": "tcp" if c.type == socket.SOCK_STREAM else "udp",
             "state": SOCK_STATES.get(c.status, str(c.status).replace("_", "-")),
             "local": fmt(c.laddr), "peer": fmt(c.raddr),
             "process": pname(c.pid) if c.pid else "", "pid": str(c.pid or "")} for c in conns]


# --------------------------------------------------------------------------
# interfaces, routes, dns
# --------------------------------------------------------------------------
def wifi_link(dev):
    info = {}
    if have("iw"):
        out = run(["iw", "dev", dev, "link"], 5)["out"]
        if "Not connected" in out:
            return {"connected": False}
        for key, pat in (("ssid", r"SSID: (.+)"), ("signal", r"signal: (-?\d+)"),
                         ("freq", r"freq: ([\d.]+)"), ("bitrate", r"tx bitrate: ([\d.]+ \S+)"),
                         ("bssid", r"Connected to ([0-9a-fA-F:]{17})")):
            m = re.search(pat, out)
            if m:
                info[key] = m.group(1).strip()
    elif have("iwconfig"):
        out = run(["iwconfig", dev], 5)["out"]
        for key, pat in (("ssid", r'ESSID:"([^"]*)"'), ("signal", r"Signal level=(-?\d+)"),
                         ("bitrate", r"Bit Rate[=:]([\d.]+ \S+)")):
            m = re.search(pat, out)
            if m:
                info[key] = m.group(1)
    if "signal" in info:
        try:
            info["signal"] = int(info["signal"])
        except ValueError:
            pass
    info["connected"] = bool(info.get("ssid"))
    return info


def interfaces():
    if IS_WIN:
        return interfaces_win()
    addr = run_json(["ip", "-j", "addr"]) or []
    link = {l.get("ifname"): l for l in (run_json(["ip", "-j", "-s", "link"]) or [])}
    out = []
    for a in addr:
        name = a.get("ifname")
        base = f"/sys/class/net/{name}"
        st = link.get(name, {}).get("stats64") or link.get(name, {}).get("stats") or {}
        rx, tx = st.get("rx", {}), st.get("tx", {})
        drv_path = f"{base}/device/driver"
        driver = os.path.basename(os.path.realpath(drv_path)) if os.path.exists(drv_path) else None
        try:
            speed = int(read(f"{base}/speed", "-1"))
        except ValueError:
            speed = -1
        flags = a.get("flags", [])
        item = {
            "name": name, "state": a.get("operstate", "UNKNOWN"), "mac": a.get("address", ""),
            "mtu": a.get("mtu"), "flags": flags, "carrier": read(f"{base}/carrier"),
            "speed": speed if speed > 0 else None, "duplex": read(f"{base}/duplex"), "driver": driver,
            "wireless": os.path.isdir(f"{base}/wireless") or os.path.exists(f"{base}/phy80211"),
            "virtual": not os.path.exists(f"{base}/device"), "loopback": "LOOPBACK" in flags,
            "ipv4": [f'{i["local"]}/{i["prefixlen"]}' for i in a.get("addr_info", []) if i.get("family") == "inet"],
            "ipv6": [f'{i["local"]}/{i["prefixlen"]}' for i in a.get("addr_info", []) if i.get("family") == "inet6"],
            "rx_bytes": rx.get("bytes"), "tx_bytes": tx.get("bytes"),
            "rx_errors": rx.get("errors", 0), "tx_errors": tx.get("errors", 0),
            "rx_dropped": rx.get("dropped", 0), "tx_dropped": tx.get("dropped", 0),
        }
        item["vendor"] = "" if item["loopback"] else vendor(item["mac"])
        if item["wireless"]:
            item["wifi"] = wifi_link(name)
        out.append(item)
    return out


def routes():
    if IS_WIN:
        return routes_win()
    r4 = run_json(["ip", "-j", "route"]) or []
    r6 = run_json(["ip", "-j", "-6", "route"]) or []
    gws = [{"gateway": r.get("gateway"), "dev": r.get("dev"), "metric": r.get("metric", 0),
            "proto": r.get("protocol")} for r in r4 if r.get("dst") == "default" and r.get("gateway")]
    gws.sort(key=lambda g: g["metric"] or 0)
    return {"ipv4": r4, "ipv6": r6, "gateways": gws}


def dns_info():
    if IS_WIN:
        return dns_info_win()
    servers, search = [], []
    for line in (read("/etc/resolv.conf", "") or "").splitlines():
        p = line.split()
        if len(p) >= 2 and p[0] == "nameserver":
            servers.append(p[1])
        elif p and p[0] in ("search", "domain"):
            search += p[1:]
    upstream = []
    stub = any(s.startswith("127.") for s in servers)
    if stub and have("resolvectl"):
        for line in run(["resolvectl", "dns"], 5)["out"].splitlines():
            if ":" not in line:
                continue
            for tok in line.split(":", 1)[1].split():
                tok = tok.split("#")[0]
                try:
                    ipaddress.ip_address(tok.split("%")[0])
                    upstream.append(tok)
                except ValueError:
                    pass
    return {"resolv_conf": servers, "upstream": sorted(set(upstream)), "search": search, "stub": stub}


def primary():
    rt = routes()
    gw = rt["gateways"][0] if rt["gateways"] else None
    ifs = interfaces()
    dev = gw["dev"] if gw else next((i["name"] for i in ifs if i["ipv4"] and not i["loopback"]), None)
    iface = next((i for i in ifs if i["name"] == dev), None)
    return gw, dev, iface, ifs, rt


def extras():
    if IS_WIN:
        return extras_win()
    out = {}
    if have("lspci"):
        out["pci"] = [l for l in run(["lspci", "-nn"])["out"].splitlines()
                      if re.search(r"ethernet|network|wireless|wi-fi", l, re.I)]
    if have("nmcli"):
        out["nmcli"] = [l.split(":") for l in
                        run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])["out"].splitlines() if l]
    if have("vnstat"):
        r = run(["vnstat"], 8)
        if r["ok"]:
            out["vnstat"] = r["out"].strip()
    return out


def overview():
    gw, dev, iface, ifs, rt = primary()
    return remember("overview", {
        "hostname": socket.gethostname(), "fqdn": socket.getfqdn(), "kernel": pyplatform.platform(terse=True) if IS_WIN else pyplatform.release(), "platform": PLATFORM,
        "user": os.environ.get("SUDO_USER") or os.environ.get("USER") or os.environ.get("USERNAME", ""), "root": IS_ROOT,
        "time": now(), "primary": dev, "gateway": gw, "interfaces": ifs, "routes": rt,
        "dns": dns_info(), "extras": extras(), "version": VERSION,
    })


# --------------------------------------------------------------------------
# neighbour discovery with names
# --------------------------------------------------------------------------
def resolve_name(ip):
    try:
        n = socket.gethostbyaddr(ip)[0]
        if n and n != ip:
            return n, "DNS"
    except Exception:  # noqa: BLE001
        pass
    n = mdns_name(ip)
    if n:
        return n, "mDNS"
    n = nbns_name(ip)
    if n:
        return n, "NetBIOS"
    return "", ""


def discover():
    gw, dev, iface, ifs, rt = primary()
    if not iface or not iface["ipv4"]:
        return remember("neighbors", {"error": "The primary interface has no IPv4 address, so there is no subnet to sweep.",
                                      "hosts": [], "count": 0})
    cidr = iface["ipv4"][0]
    my_ip = cidr.split("/")[0]
    ifc = ipaddress.ip_interface(cidr)
    net = ifc.network if ifc.network.prefixlen >= 24 else ipaddress.ip_network(f"{ifc.ip}/24", strict=False)
    alive, method = set(), "neighbour table only"
    if net.num_addresses > 2:
        if IS_WIN and not have("nmap"):
            alive |= win_sweep(net)
            method = "ping sweep"
        elif have("fping"):
            r = run(["fping", "-a", "-q", "-r", "1", "-t", "300", "-g", str(net)], 90)
            alive |= {l.strip() for l in r["out"].splitlines() if l.strip()}
            method = "fping sweep"
        elif have("nmap"):
            r = run(["nmap", "-sn", "-n", "-T4", str(net), "-oG", "-"], 120)
            alive |= set(re.findall(r"Host: (\S+) .*Status: Up", r["out"]))
            method = "nmap -sn"
        else:
            hosts = [str(h) for h in net.hosts()]
            with cf.ThreadPoolExecutor(64) as ex:
                for h, r in zip(hosts, ex.map(lambda h: run(["ping", "-n", "-c1", "-W1", h], 3), hosts)):
                    if r["ok"]:
                        alive.add(h)
            method = "ping sweep"
    time.sleep(0.3)
    table = {}
    for n in neigh_table(dev):
        ip = n.get("dst", "")
        if ":" in ip:
            continue
        st = n.get("state") or ["?"]
        table[ip] = {"ip": ip, "mac": n.get("lladdr", ""), "state": st[0] if isinstance(st, list) else st}
    for ip in alive:
        table.setdefault(ip, {"ip": ip, "mac": "", "state": "ALIVE"})
    table.pop(my_ip, None)
    hosts = [h for h in table.values() if not (h["state"] in ("FAILED", "INCOMPLETE") and h["ip"] not in alive)]
    ex = cf.ThreadPoolExecutor(32)
    futs = [ex.submit(resolve_name, h["ip"]) for h in hosts]
    gw_ip = gw["gateway"] if gw else None
    for h, f in zip(hosts, futs):
        try:
            name, src = f.result(timeout=12)
        except Exception:  # noqa: BLE001
            name, src = "", ""
        h.update(name=name, name_source=src, vendor=vendor(h["mac"]),
                 alive=h["ip"] in alive or h["state"] in ("REACHABLE", "DELAY", "PROBE", "PERMANENT"),
                 role="Gateway" if h["ip"] == gw_ip else "")
        h["kind"] = "router" if h["role"] == "Gateway" else device_kind(guess_type([], h["vendor"]))
    ex.shutdown(wait=False)
    hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    me = {"kind": "computer", "ip": my_ip, "mac": iface["mac"], "name": socket.gethostname(), "name_source": "this host",
          "vendor": vendor(iface["mac"]), "state": "SELF", "alive": True, "role": "This host"}
    return remember("neighbors", {"network": str(net), "interface": dev, "method": method,
                                  "hosts": [me] + hosts, "count": len(hosts), "time": now()})


COMMON_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
                110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
                445: "smb", 515: "printer", 548: "afp", 554: "rtsp", 631: "ipp", 993: "imaps",
                995: "pop3s", 1883: "mqtt", 3306: "mysql", 3389: "rdp", 5000: "upnp", 5432: "postgresql",
                5900: "vnc", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8443: "https-alt",
                9100: "jetdirect", 32400: "plex", 49152: "upnp", 62078: "iphone-sync"}


def guess_type(ports, vend):
    p = {x["port"] for x in ports}
    v = (vend or "").lower()
    if p & {9100, 515, 631}:
        return "Printer"
    if 62078 in p or "apple" in v:
        return "Apple device"
    if 3389 in p or {135, 445} <= p:
        return "Windows PC or server"
    if 554 in p or any(k in v for k in ("hikvision", "dahua", "axis")):
        return "IP camera / NVR"
    if any(k in v for k in ("vmware", "nutanix", "qemu", "xensource", "microsoft")):
        return "Virtual machine"
    if any(k in v for k in ("cisco", "juniper", "aruba", "ubiquiti", "mikrotik", "tp-link", "netgear",
                            "fortinet", "zte", "arris", "technicolor", "sagemcom")):
        return "Network equipment (router, switch, AP or modem)"
    if 53 in p and (80 in p or 443 in p):
        return "Router / firewall / DNS appliance"
    if 32400 in p:
        return "Media server"
    if 22 in p:
        return "Linux/Unix host or managed network device"
    if any(k in v for k in ("samsung", "xiaomi", "oppo", "vivo", "oneplus", "motorola", "google", "huawei")):
        return "Phone, tablet or smart device"
    if v.startswith("private"):
        return "Phone or laptop using a private MAC"
    if not p:
        return "Unknown (nothing common open: phone, IoT or firewalled host)"
    return "Unknown"


def device_kind(guess):
    g = guess.lower()
    for key, kind in (("printer", "printer"), ("camera", "camera"), ("virtual", "server"), ("server", "server"),
                      ("network equipment", "router"), ("router", "router"), ("phone", "phone"),
                      ("apple", "phone"), ("windows", "computer"), ("linux", "computer")):
        if key in g:
            return kind
    return "unknown"


def scan_host(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "Invalid IP"}
    ports, method = [], ""
    if have("nmap"):
        r = run(["nmap", "-Pn", "-T4", "-F", "--open", "-oG", "-", ip], 150)
        m = re.search(r"Ports: (.+?)(\t|$)", r["out"])
        if m:
            for part in m.group(1).split(","):
                f = part.strip().split("/")
                if len(f) >= 5 and f[1] == "open":
                    ports.append({"port": int(f[0]), "proto": f[2], "service": f[4] or COMMON_PORTS.get(int(f[0]), "")})
        method = "nmap -F (top 100 ports)"
    else:
        def probe(port):
            try:
                with socket.create_connection((ip, port), 0.8):
                    return port
            except OSError:
                return None
        with cf.ThreadPoolExecutor(32) as ex:
            for p in ex.map(probe, COMMON_PORTS):
                if p:
                    ports.append({"port": p, "proto": "tcp", "service": COMMON_PORTS[p]})
        method = f"TCP connect scan of {len(COMMON_PORTS)} common ports (install nmap for more)"
    vend = ""
    with STATE_LOCK:
        nb = STATE.get("neighbors", {}).get("data", {})
    for h in nb.get("hosts", []):
        if h["ip"] == ip:
            vend = h.get("vendor", "")
    g = guess_type(ports, vend)
    return {"ip": ip, "method": method, "ports": sorted(ports, key=lambda x: x["port"]), "guess": g, "kind": device_kind(g)}


# --------------------------------------------------------------------------
# SSH launcher: open a terminal with "ssh user@host" ready to go
#
# NetPane never handles the password. It builds the exact ssh command and
# opens the machine's own terminal, so the key exchange and the password
# prompt happen in that terminal, under the logged-in user, not in the web
# UI and not as root. This is a convenience for logging in to kit you
# administer (routers, switches, servers), nothing more.
# --------------------------------------------------------------------------
SSH_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
# Linux terminals, in order of preference. Each entry is (binary, args-before-command).
# The ssh command is appended as one final string argument after these args.
_LINUX_TERMS = [
    ("x-terminal-emulator", ["-e"]),
    ("gnome-terminal", ["--"]),
    ("konsole", ["-e"]),
    ("xfce4-terminal", ["-x"]),
    ("mate-terminal", ["-x"]),
    ("tilix", ["-e"]),
    ("kitty", []),
    ("alacritty", ["-e"]),
    ("foot", []),
    ("xterm", ["-e"]),
]


def _ssh_argv(host, user, port):
    """The ssh command as a list, with options that make an interactive login behave."""
    argv = ["ssh"]
    if port and int(port) != 22:
        argv += ["-p", str(int(port))]
    # Ask for a password politely, never hang forever on an unreachable host.
    argv += ["-o", "ConnectTimeout=10", "-o", "NumberOfPasswordPrompts=3"]
    argv.append(f"{user}@{host}" if user else host)
    return argv


def _terminal_ssh(host, user, port):
    """Open the system terminal running ssh. Returns (ok, terminal_name_or_error)."""
    argv = _ssh_argv(host, user, port)
    ssh_str = " ".join(shlex.quote(c) for c in argv)

    if IS_WIN:
        # start a new console window that stays open after ssh exits (/k)
        try:
            subprocess.Popen(["cmd", "/c", "start", "", "cmd", "/k", ssh_str],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, shell=False)
            return True, "Windows console", ssh_str
        except OSError as e:
            return False, f"Could not open a console: {e}", ssh_str

    if sys.platform == "darwin":
        script = f'tell application "Terminal" to do script "{ssh_str}" activate'
        try:
            subprocess.Popen(["osascript", "-e", script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL)
            return True, "Terminal.app", ssh_str
        except OSError as e:
            return False, f"Could not open Terminal: {e}", ssh_str

    # Linux: keep the window open after ssh finishes so any error is readable.
    held = f"{ssh_str}; echo; echo '[ssh session ended — press Enter to close]'; read _"
    for binary, pre in _LINUX_TERMS:
        if not have(binary):
            continue
        if binary in ("gnome-terminal", "tilix", "xfce4-terminal", "mate-terminal"):
            cmd = [binary] + pre + ["bash", "-lc", held]
        elif binary in ("kitty", "foot"):
            cmd = [binary, "bash", "-lc", held]
        else:  # x-terminal-emulator, konsole, alacritty, xterm
            cmd = [binary] + pre + [f"bash -lc {shlex.quote(held)}"]
        if _launch_as_user(cmd):
            return True, binary, ssh_str
    return False, "no-terminal", ssh_str


def ssh_launch(host, user, port):
    """Validate the request and open a terminal. Never receives or forwards a password."""
    host = (host or "").strip()
    user = (user or "").strip()
    # Accept an IP, or a plain hostname made of label characters. Nothing that
    # could smuggle shell metacharacters or extra ssh options.
    ok_host = False
    try:
        ipaddress.ip_address(host)
        ok_host = True
    except ValueError:
        ok_host = bool(re.match(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$", host))
    if not ok_host:
        return {"ok": False, "error": "That host is not a valid IP address or hostname."}
    if user and not SSH_USER_RE.match(user):
        return {"ok": False, "error": "Username can use letters, numbers, dot, dash and underscore only."}
    try:
        port = int(port or 22)
    except (TypeError, ValueError):
        return {"ok": False, "error": "Port must be a number."}
    if not 1 <= port <= 65535:
        return {"ok": False, "error": "Port must be between 1 and 65535."}

    ok, term, ssh_str = _terminal_ssh(host, user, port)
    if ok:
        return {"ok": True, "terminal": term, "cmd": ssh_str,
                "note": "A terminal window opened on this machine. Type the password there."}
    if term == "no-terminal":
        return {"ok": False, "no_terminal": True, "cmd": ssh_str,
                "error": "No terminal program was found to open. Copy the command and run it yourself."}
    return {"ok": False, "cmd": ssh_str, "error": term}


# --------------------------------------------------------------------------
# Intel lookups: passive, public-data queries about domains, IPs and hosts.
# Everything here is read-only and about infrastructure, not people. Most of
# it needs no API key, in keeping with NetPane's light footprint.
# --------------------------------------------------------------------------
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z0-9-]{1,63})+\.?$")


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _http_json(url, timeout=8):
    """GET a URL and parse JSON. Returns (data, error)."""
    req = urllib.request.Request(url, headers={"User-Agent": "NetPane/" + VERSION, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, "not found (404)"
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, str(getattr(e, "reason", e))


def _resolver():
    """Pick a usable resolver: the system one if it is a real server, else a public fallback."""
    info = dns_info()
    for s in info.get("resolv_conf", []) + info.get("upstream", []):
        if not s.startswith("127."):
            return s
    return "1.1.1.1"


# ----- DNS records (A, AAAA, NS, MX, SOA, TXT, CAA, SPF, DMARC) -----
def _dns_records_query(server, name, qtype, timeout=3.0):
    """A fuller DNS query than dns_query(): parses the record types a lookup needs."""
    tid = random.randint(0, 0xFFFF)
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + _qname(name) + struct.pack(">HH", qtype, 1)
    host = server.split("%")[0]
    try:
        s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as e:
        return {"rcode": -1, "err": str(e), "records": []}
    t0 = time.time()
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (host, 53))
        while True:
            if time.time() - t0 > timeout:
                raise socket.timeout()
            s.settimeout(timeout - (time.time() - t0))
            data, _ = s.recvfrom(8192)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid:
                break
    except socket.timeout:
        return {"rcode": -1, "err": "timed out", "records": []}
    except OSError as e:
        return {"rcode": -1, "err": str(e), "records": []}
    finally:
        s.close()
    try:
        rflags, qd, an = struct.unpack(">HHH", data[2:8])
        off = 12
        for _ in range(qd):
            _, off = _dns_name(data, off)
            off += 4
        recs = []
        for _ in range(an):
            _, off = _dns_name(data, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rd = data[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                recs.append(("A", socket.inet_ntoa(rd)))
            elif rtype == 28 and rdlen == 16:
                recs.append(("AAAA", socket.inet_ntop(socket.AF_INET6, rd)))
            elif rtype == 2:
                recs.append(("NS", _dns_name(data, off)[0].rstrip(".")))
            elif rtype == 5:
                recs.append(("CNAME", _dns_name(data, off)[0].rstrip(".")))
            elif rtype == 15:
                pref = struct.unpack(">H", rd[:2])[0]
                recs.append(("MX", f"{pref} {_dns_name(data, off + 2)[0].rstrip('.')}"))
            elif rtype == 6:
                mname, o2 = _dns_name(data, off)
                rname, o3 = _dns_name(data, o2)
                serial = struct.unpack(">I", data[o3:o3 + 4])[0] if o3 + 4 <= len(data) else "?"
                recs.append(("SOA", f"{mname.rstrip('.')} {rname.rstrip('.')} serial {serial}"))
            elif rtype == 16:
                txt, p = "", 0
                while p < len(rd):
                    ln = rd[p]
                    txt += rd[p + 1:p + 1 + ln].decode("utf-8", "replace")
                    p += 1 + ln
                recs.append(("TXT", txt))
            elif rtype == 257:
                flags = rd[0]
                tl = rd[1]
                tag = rd[2:2 + tl].decode("ascii", "replace")
                val = rd[2 + tl:].decode("utf-8", "replace")
                recs.append(("CAA", f"{flags} {tag} \"{val}\""))
            off += rdlen
        return {"rcode": rflags & 0xF, "err": "", "records": recs}
    except (ValueError, struct.error, IndexError):
        return {"rcode": -1, "err": "malformed reply", "records": []}


def dns_records(domain):
    domain = (domain or "").strip().rstrip(".").lower()
    if not _DOMAIN_RE.match(domain + "."):
        return {"error": "Enter a domain name, for example example.com."}
    server = _resolver()
    sets = {}
    for label, qt in [("A", 1), ("AAAA", 28), ("NS", 2), ("MX", 15), ("SOA", 6), ("TXT", 16), ("CAA", 257)]:
        r = _dns_records_query(server, domain, qt)
        vals = [v for (t, v) in r["records"]]
        if vals:
            sets[label] = vals
    # Mail posture: SPF lives in the domain's TXT; DMARC in _dmarc.<domain>.
    spf = [v for v in sets.get("TXT", []) if v.lower().startswith("v=spf1")]
    dmarc_r = _dns_records_query(server, "_dmarc." + domain, 16)
    dmarc = [v for (_, v) in dmarc_r["records"] if v.lower().startswith("v=dmarc1")]
    mail = {
        "spf": spf[0] if spf else "",
        "dmarc": dmarc[0] if dmarc else "",
        "spf_note": "present" if spf else "no SPF record found",
        "dmarc_note": "present" if dmarc else "no DMARC record found",
    }
    return {"domain": domain, "resolver": server, "records": sets, "mail": mail}


# ----- WHOIS over port 43 (domains and IPs), following IANA referral -----
def _whois_raw(server, query, timeout=8):
    try:
        with socket.create_connection((server, 43), timeout) as s:
            s.sendall((query + "\r\n").encode())
            buf = b""
            s.settimeout(timeout)
            while len(buf) < 200000:
                try:
                    chunk = s.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
            return buf.decode("utf-8", "replace")
    except OSError as e:
        return f"__error__ {e}"


def whois_lookup(target):
    target = (target or "").strip().lower().rstrip(".")
    is_ip = _is_ip(target)
    if not is_ip and not _DOMAIN_RE.match(target + "."):
        return {"error": "Enter a domain name or IP address."}
    # IANA knows which whois server is authoritative; follow its referral once.
    top = _whois_raw("whois.iana.org", target)
    refer = ""
    for line in top.splitlines():
        m = re.match(r"(?:refer|whois):\s*(\S+)", line.strip(), re.I)
        if m:
            refer = m.group(1)
            break
    text = top
    server = "whois.iana.org"
    if refer and not refer.startswith("__error__"):
        second = _whois_raw(refer, target)
        if second and not second.startswith("__error__"):
            text = second
            server = refer
    if text.startswith("__error__"):
        return {"error": "WHOIS server did not answer.", "detail": text}
    # Trim the long legal boilerplate most registries append.
    lines = [l for l in text.splitlines() if not l.strip().startswith("%") and not l.strip().startswith("#")]
    trimmed = "\n".join(lines).strip()
    if len(trimmed) > 6000:
        trimmed = trimmed[:6000] + "\n...[truncated]"
    return {"target": target, "server": server, "kind": "ip" if is_ip else "domain", "text": trimmed}


# ----- RDAP (structured WHOIS) via the public rdap.org bootstrap -----
def rdap_lookup(target):
    target = (target or "").strip().lower().rstrip(".")
    is_ip = _is_ip(target)
    if not is_ip and not _DOMAIN_RE.match(target + "."):
        return {"error": "Enter a domain name or IP address."}
    kind = "ip" if is_ip else "domain"
    data, err = _http_json(f"https://rdap.org/{kind}/{target}", timeout=10)
    if err:
        return {"error": f"RDAP lookup failed: {err}"}
    out = {"target": target, "kind": kind, "handle": data.get("handle", ""), "name": data.get("name", ""),
           "status": data.get("status", []), "events": [], "entities": []}
    for ev in data.get("events", []):
        out["events"].append({"action": ev.get("eventAction", ""), "date": ev.get("eventDate", "")})
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        name = ent.get("handle", "")
        vc = ent.get("vcardArray")
        if isinstance(vc, list) and len(vc) > 1:
            for field in vc[1]:
                if isinstance(field, list) and field and field[0] == "fn":
                    name = field[3] if len(field) > 3 else name
        out["entities"].append({"roles": roles, "name": name})
    if is_ip:
        out["range"] = f"{data.get('startAddress', '')} - {data.get('endAddress', '')}"
        out["country"] = data.get("country", "")
    return out


# ----- TLS/SSL certificate inspector -----
def tls_cert(host, port=443):
    import ssl
    host = (host or "").strip()
    if ":" in host and not _is_ip(host):
        host, _, p = host.partition(":")
        if p.isdigit():
            port = int(p)
    if not host or (not _is_ip(host) and not _DOMAIN_RE.match(host + ".")):
        return {"error": "Enter a hostname or IP address."}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we inspect the cert, we are not validating a connection
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host if not _is_ip(host) else None) as ss:
                cert = ss.getpeercert(binary_form=False)
                der = ss.getpeercert(binary_form=True)
                cipher = ss.cipher()
                proto = ss.version()
    except ssl.SSLError as e:
        return {"error": f"TLS handshake failed: {e}"}
    except OSError as e:
        return {"error": f"Could not connect to {host}:{port}: {e}"}
    if not cert and der:
        # Rare: no parsed dict (self-signed under some stacks). Report what we can.
        return {"host": host, "port": port, "proto": proto, "cipher": cipher[0] if cipher else "",
                "note": "The peer presented a certificate that could not be parsed into fields (often self-signed)."}
    subj = {k: v for t in cert.get("subject", []) for (k, v) in t}
    issuer = {k: v for t in cert.get("issuer", []) for (k, v) in t}
    sans = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]
    not_after = cert.get("notAfter", "")
    days_left = None
    try:
        exp = ssl.cert_time_to_seconds(not_after)
        days_left = round((exp - time.time()) / 86400)
    except Exception:  # noqa: BLE001
        pass
    return {"host": host, "port": port, "proto": proto, "cipher": cipher[0] if cipher else "",
            "subject": subj.get("commonName", ""), "issuer": issuer.get("commonName", "") or issuer.get("organizationName", ""),
            "valid_from": cert.get("notBefore", ""), "valid_to": not_after, "days_left": days_left,
            "sans": sans[:50], "san_count": len(sans)}


# ----- ASN / BGP origin via Team Cymru's whois service -----
def asn_lookup(ip):
    ip = (ip or "").strip()
    if not _is_ip(ip):
        return {"error": "Enter an IP address."}
    # Cymru bulk mode returns: AS | IP | BGP prefix | CC | registry | allocated | AS name
    q = f"begin\nverbose\n{ip}\nend\n"
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=8) as s:
            s.sendall(q.encode())
            buf = b""
            s.settimeout(8)
            while True:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
    except OSError as e:
        return {"error": f"ASN lookup failed: {e}"}
    lines = [l for l in buf.decode("utf-8", "replace").splitlines() if l and "|" in l]
    data = [l for l in lines if not l.lower().startswith("as ")]
    if not data:
        return {"error": "No ASN data returned for that IP."}
    f = [x.strip() for x in data[0].split("|")]
    if len(f) < 7:
        return {"error": "Unexpected ASN response.", "raw": data[0]}
    return {"ip": f[1], "asn": f[0], "prefix": f[2], "country": f[3], "registry": f[4],
            "allocated": f[5], "as_name": f[6]}


# ----- Public exposure via Shodan's free, keyless InternetDB -----
def exposure_lookup(ip):
    ip = (ip or "").strip()
    if not _is_ip(ip):
        return {"error": "Enter an IP address."}
    if ipaddress.ip_address(ip).is_private:
        return {"error": "That is a private address. InternetDB only indexes public IPs."}
    data, err = _http_json(f"https://internetdb.shodan.io/{ip}", timeout=10)
    if err == "not found (404)":
        return {"ip": ip, "ports": [], "hostnames": [], "tags": [], "vulns": [], "cpes": [],
                "note": "Shodan has nothing indexed for this address. Often that means it exposes nothing public."}
    if err:
        return {"error": f"Exposure lookup failed: {err}"}
    return {"ip": data.get("ip", ip), "ports": data.get("ports", []), "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []), "vulns": data.get("vulns", []), "cpes": data.get("cpes", [])}


LOOKUPS = {"dns": lambda t: dns_records(t), "whois": lambda t: whois_lookup(t),
           "rdap": lambda t: rdap_lookup(t), "tls": lambda t: tls_cert(t),
           "asn": lambda t: asn_lookup(t), "exposure": lambda t: exposure_lookup(t)}


def lookup(kind, target):
    fn = LOOKUPS.get(kind)
    if not fn:
        return {"error": "Unknown lookup."}
    target = (target or "").strip()
    if not target:
        return {"error": "Enter a target first."}
    if len(target) > 255 or any(c in target for c in " \t\r\n\"'`;|&$<>()"):
        return {"error": "That target has characters that are not allowed."}
    try:
        return fn(target)
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


# --------------------------------------------------------------------------
# VLAN: what 802.1Q tag, if any, this host sits on, and whether a switch is
# telling us the port/native VLAN over LLDP or CDP.
# --------------------------------------------------------------------------
def vlan_tagged():
    """802.1Q subinterfaces configured on this host (instant, no capture)."""
    out = []
    if IS_WIN:
        # Best effort: adapters may expose a VlanID advanced property.
        r = run(["powershell", "-NoProfile", "-Command",
                 "Get-NetAdapterAdvancedProperty -DisplayName 'VLAN ID' -ErrorAction SilentlyContinue | "
                 "Select-Object -Property Name,DisplayValue | ConvertTo-Json -Compress"], 10)
        try:
            data = json.loads(r["out"]) if r["out"].strip() else []
            if isinstance(data, dict):
                data = [data]
            for a in data:
                vid = str(a.get("DisplayValue", "")).strip()
                if vid and vid != "0":
                    out.append({"name": a.get("Name", ""), "id": vid, "parent": "", "protocol": "802.1Q"})
        except (ValueError, TypeError):
            pass
        return out
    links = run_json(["ip", "-d", "-j", "link", "show"]) or []
    for l in links:
        li = l.get("linkinfo") or {}
        if li.get("info_kind") == "vlan":
            idata = li.get("info_data") or {}
            out.append({"name": l.get("ifname", ""), "id": idata.get("id"),
                        "parent": l.get("link", ""), "protocol": idata.get("protocol", "802.1Q")})
    if not out:  # fallback for older kernels
        cfg = read("/proc/net/vlan/config", "") or ""
        for line in cfg.splitlines():
            if "|" in line and "VLAN" not in line.split("|")[0]:
                p = [x.strip() for x in line.split("|")]
                if len(p) >= 3 and p[1].isdigit():
                    out.append({"name": p[0], "id": int(p[1]), "parent": p[2], "protocol": "802.1Q"})
    return out


def vlan_scan():
    tagged = vlan_tagged()
    return {"tagged": tagged, "has_tag": bool(tagged),
            "lldp_supported": bool(have("lldpctl")) or (IS_ROOT and not IS_WIN),
            "platform": PLATFORM, "is_root": IS_ROOT}


def _lldp_id(subtype, rest):
    if subtype == 4 and len(rest) == 6:  # MAC
        return ":".join("%02x" % b for b in rest)
    try:
        s = rest.decode("utf-8")
        if s.isprintable() and s:
            return s
    except UnicodeDecodeError:
        pass
    if len(rest) == 6:
        return ":".join("%02x" % b for b in rest)
    return rest.hex()


def _parse_lldp(frame):
    if len(frame) < 16 or frame[12:14] != b"\x88\xcc":
        return None
    data = frame[14:]
    i, out, vlans = 0, {"proto": "LLDP"}, []
    while i + 2 <= len(data):
        h = int.from_bytes(data[i:i + 2], "big")
        ttype, tlen = h >> 9, h & 0x1FF
        i += 2
        val = data[i:i + tlen]
        i += tlen
        if ttype == 0:
            break
        if ttype == 1 and val:
            out["chassis"] = _lldp_id(val[0], val[1:])
        elif ttype == 2 and val:
            out["port"] = _lldp_id(val[0], val[1:])
        elif ttype == 4:
            out["port_descr"] = val.decode("utf-8", "replace")
        elif ttype == 5:
            out["system"] = val.decode("utf-8", "replace")
        elif ttype == 127 and len(val) >= 4 and val[0:3] == b"\x00\x80\xc2":
            sub, body = val[3], val[4:]
            if sub == 1 and len(body) >= 2:
                out["pvid"] = int.from_bytes(body[0:2], "big")
            elif sub == 3 and len(body) >= 3:
                vid = int.from_bytes(body[0:2], "big")
                nlen = body[2]
                vlans.append({"id": vid, "name": body[3:3 + nlen].decode("utf-8", "replace")})
    if vlans:
        out["vlans"] = vlans
    return out


def _parse_cdp(frame):
    if len(frame) < 22 or frame[0:6] != b"\x01\x00\x0c\xcc\xcc\xcc":
        return None
    data = frame[14:]
    if data[:8] != b"\xaa\xaa\x03\x00\x00\x0c\x20\x00":
        return None
    cdp = data[8:]
    i, out = 4, {"proto": "CDP"}
    while i + 4 <= len(cdp):
        ttype = int.from_bytes(cdp[i:i + 2], "big")
        tlen = int.from_bytes(cdp[i + 2:i + 4], "big")
        if tlen < 4 or i + tlen > len(cdp):
            break
        val = cdp[i + 4:i + tlen]
        i += tlen
        if ttype == 0x0001:
            out["system"] = val.decode("utf-8", "replace")
        elif ttype == 0x0003:
            out["port"] = val.decode("utf-8", "replace")
        elif ttype == 0x000A and len(val) >= 2:
            out["native_vlan"] = int.from_bytes(val[0:2], "big")
    return out


def _lldpctl_neighbors():
    r = run(["lldpctl", "-f", "keyvalue"], 8)
    if not r["ok"] or not r["out"].strip():
        return []
    ifaces = {}
    for line in r["out"].splitlines():
        if "=" not in line or not line.startswith("lldp."):
            continue
        key, _, val = line.partition("=")
        parts = key.split(".")
        if len(parts) < 3:
            continue
        ifc = ifaces.setdefault(parts[1], {"proto": "LLDP", "iface": parts[1]})
        rest = ".".join(parts[2:])
        if rest == "chassis.name":
            ifc["system"] = val
        elif rest == "port.descr":
            ifc["port_descr"] = val
        elif rest in ("port.ifname", "port.local"):
            ifc.setdefault("port", val)
        elif rest == "vlan.vlan-id":
            ifc["pvid"] = val
    return list(ifaces.values())


def lldp_listen(timeout=65):
    """Learn the switch, port and VLAN from one LLDP or CDP advertisement."""
    if have("lldpctl"):
        n = _lldpctl_neighbors()
        if n:
            return {"ok": True, "source": "lldpctl", "neighbors": n}
    if IS_WIN:
        return {"ok": False, "reason": "Windows has no built-in LLDP capture. Install lldpd, or read the VLAN off the switch."}
    if not IS_ROOT:
        return {"ok": False, "reason": "Listening for LLDP/CDP needs root. Start NetPane with sudo, or install lldpd."}
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except (AttributeError, OSError) as e:
        return {"ok": False, "reason": f"Raw capture is not available here: {e}"}
    timeout = max(10, min(int(timeout), 80))
    deadline = time.time() + timeout
    lldp = cdp = None
    try:
        gw, dev, iface, ifs, rt = primary()
        if dev:
            try:
                s.bind((dev, 0))
            except OSError:
                pass
        while time.time() < deadline and not (lldp and cdp):
            s.settimeout(max(0.5, min(deadline - time.time(), 5)))
            try:
                frame = s.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if not lldp:
                lldp = _parse_lldp(frame)
            if not cdp:
                cdp = _parse_cdp(frame)
    finally:
        s.close()
    neigh = [x for x in (lldp, cdp) if x]
    if not neigh:
        return {"ok": True, "source": "capture", "neighbors": [],
                "note": "No LLDP or CDP frame arrived in the listening window. The switch may not run either, "
                        "or the port has discovery turned off."}
    return {"ok": True, "source": "capture", "neighbors": neigh}


# --------------------------------------------------------------------------
# probes used by the health check
# --------------------------------------------------------------------------
def parse_ping(out):
    loss = re.search(r"([\d.]+)% packet loss", out)
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    return {"loss": float(loss.group(1)) if loss else 100.0,
            "min": float(rtt.group(1)) if rtt else None, "avg": float(rtt.group(2)) if rtt else None,
            "max": float(rtt.group(3)) if rtt else None, "mdev": float(rtt.group(4)) if rtt else None}


def ping(host, count=4):
    if IS_WIN:
        r = run(["ping", "-n", str(count), "-w", "1000", host], count * 2 + 6)
        p = parse_ping_win(r["out"], count)
        p["host"] = host
        return p
    r = run(["ping", "-n", "-c", str(count), "-i", "0.2", "-W", "1", "-w", str(max(4, count)), host], count + 8)
    p = parse_ping(r["out"])
    p["host"] = host
    return p


def tcp_probe(host, port, timeout=3):
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout):
            return {"host": host, "port": port, "ok": True, "ms": round((time.time() - t0) * 1000)}
    except OSError as e:
        return {"host": host, "port": port, "ok": False, "err": str(e)}


def dns_probe(server, name):
    r = dns_query(server, name, 1, timeout=2.5)
    return {"ok": r["ok"], "ms": r["ms"], "err": r.get("err", "")}


def sys_resolve(name):
    t0 = time.time()
    try:
        infos = socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
        return {"ok": True, "ms": round((time.time() - t0) * 1000), "ip": infos[0][4][0]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "ms": round((time.time() - t0) * 1000), "err": str(e)}


def http_probe(url):
    t0 = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": "NetPane/" + VERSION})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return {"ok": True, "code": r.status, "final": r.geturl(), "ms": round((time.time() - t0) * 1000)}
    except urllib.error.HTTPError as e:
        return {"ok": True, "code": e.code, "final": e.geturl() or url, "ms": round((time.time() - t0) * 1000)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "err": str(getattr(e, "reason", e)), "ms": round((time.time() - t0) * 1000)}


def public_ip():
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "curl/8"}), timeout=5) as r:
                ip = r.read().decode().strip()
                ipaddress.ip_address(ip)
                return ip
        except Exception:  # noqa: BLE001
            continue
    return None


def _df_ping(target, payload, count=1):
    """Ping with Don't Fragment set. Returns (passed, mtu_reported_by_router, local_error_mtu)."""
    if IS_WIN:
        r = run(["ping", "-f", "-l", str(payload), "-n", str(count), "-w", "1000", target], count * 2 + 4)
        passed = "TTL=" in r["out"].upper()
        return passed, (-1 if (not passed and "DF" in r["out"]) else None), None
    r = run(["ping", "-n", "-c", str(count), "-W", "1", "-M", "do", "-s", str(payload), target], count + 4)
    text = r["out"] + "\n" + r["err"]
    passed = parse_ping(r["out"])["loss"] < 100
    local = re.search(r"local error.*?mtu\s*=\s*(\d+)", text, re.I)
    remote = re.search(r"Frag(?:mentation)? needed.*?mtu\s*=\s*(\d+)", text, re.I)
    return passed, int(remote.group(1)) if remote else None, int(local.group(1)) if local else None


def mtu_probe(target, iface_mtu=None):
    """Find the exact path MTU and whether routers report it (PMTUD works) or drop silently (black hole)."""
    local = iface_mtu or 1500
    passed, reported, local_err = _df_ping(target, local - 28, 2)
    if passed:
        return {"full": True, "mtu": local, "iface_mtu": local, "pmtud": True}
    if local_err and local_err < local:
        # The kernel refused locally because it already learned a smaller path MTU for this
        # destination from a router's "fragmentation needed" message. PMTUD is working.
        ok, _, _ = _df_ping(target, local_err - 28, 2)
        if ok:
            return {"full": False, "mtu": local_err, "iface_mtu": local, "pmtud": True, "reported": local_err}
    # binary search the largest payload that gets through
    lo, hi, best = 548, local - 29, None
    while lo <= hi:
        mid = (lo + hi) // 2
        ok, rep, _ = _df_ping(target, mid)
        reported = reported or rep
        if ok:
            best, lo = mid, mid + 1
        else:
            hi = mid - 1
    mtu = best + 28 if best is not None else None
    if reported == -1:  # Windows says "needs to be fragmented" but not the size
        reported = mtu
    return {"full": False, "mtu": mtu, "iface_mtu": local, "pmtud": reported is not None,
            "reported": reported}


def gateway_arp(gw, dev):
    if IS_ROOT and have("arping"):
        r = run(["arping", "-c", "2", "-w", "3", "-I", dev, gw], 6)
        if r["ok"]:
            m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", r["out"])
            return True, f"Gateway {gw} answered ARP{(' from ' + m.group(1)) if m else ''}."
    for e in neigh_table(None if not IS_WIN else dev, gw):
        st = e.get("state") or []
        if e.get("lladdr") and not set(st) & {"FAILED", "INCOMPLETE"}:
            v = vendor(e["lladdr"])
            return True, f"Gateway {gw} is at {e['lladdr']}{' (' + v + ')' if v else ''}, ARP state {'/'.join(st)}."
    return False, f"No ARP reply from gateway {gw}. Layer 2 between this host and the gateway is broken."


# --------------------------------------------------------------------------
# layered health check and verdict
# --------------------------------------------------------------------------
ORDER = ["Physical link", "IP address", "Default route", "Gateway ARP", "Gateway ping", "Internet by IP",
         "TCP egress", "MTU / fragmentation", "DNS servers", "Name resolution", "HTTPS",
         "Captive portal / proxy", "Line quality"]

LAYER = {"Physical link": "L1", "IP address": "L3", "Default route": "L3", "Gateway ARP": "L2",
         "Gateway ping": "L3", "Internet by IP": "L3", "TCP egress": "L4", "MTU / fragmentation": "L3",
         "DNS servers": "L7", "Name resolution": "L7", "HTTPS": "L7", "Captive portal / proxy": "L7",
         "Line quality": "Perf"}

RULES_OUT = {
    "Physical link": "Cable, switch port, NIC and Wi-Fi association",
    "IP address": "DHCP and IP assignment",
    "Default route": "Local routing config",
    "Gateway ARP": "LAN segment and VLAN to the gateway",
    "Gateway ping": "The gateway itself being down",
    "Internet by IP": "Router WAN link and ISP reachability",
    "TCP egress": "Outbound firewall on TCP 443",
    "MTU / fragmentation": "MTU and fragmentation on the path",
    "DNS servers": "Each configured DNS server",
    "Name resolution": "Name resolution on this host",
    "HTTPS": "Web access and TLS",
    "Captive portal / proxy": "Captive portals and transparent proxies",
    "Line quality": "Packet loss, latency and jitter",
}

DOMAIN = {
    "Physical link": ("this machine's physical connection",
                      "The interface has no link, so nothing above layer 1 can work.",
                      ["Reseat or swap the patch cable and try a different switch port.",
                       "Check link lights on the NIC and the switch.",
                       "For Wi-Fi, confirm the SSID and password and move closer to the AP.",
                       W("Run: ethtool <iface> and ip link to confirm.", "In PowerShell, run: Get-NetAdapter | Format-List Name,Status,LinkSpeed")]),
    "IP address": ("IP addressing (DHCP)",
                   "The link is up but this host never got a usable IPv4 address.",
                   ["Confirm the DHCP server is up and the scope is not exhausted.",
                    "Check the switch port is on the right VLAN.",
                    W("Retry: sudo dhclient -v <iface> or nmcli con up <name>.", "Retry: ipconfig /release, then ipconfig /renew."),
                    "Set a static IP temporarily to prove the segment works."]),
    "Default route": ("this machine's routing setup",
                      "There is no default gateway, so only the local subnet is reachable.",
                      ["Check DHCP option 3 (router) or the static config.",
                       W("Add one to test: sudo ip route add default via <gateway-ip>.", "Add one to test (as administrator): route add 0.0.0.0 mask 0.0.0.0 <gateway-ip>")]),
    "Gateway ARP": ("the local network segment or VLAN",
                    "This host cannot reach the gateway at layer 2.",
                    ["Verify the VLAN on the switch port and the subnet mask on this host.",
                     "Check port security, 802.1X or MAC filtering on the switch.",
                     "Confirm the gateway interface is up."]),
    "Gateway ping": ("the gateway (your router or firewall)",
                     "The gateway is not answering.",
                     ["Check the router or firewall is powered and its LAN interface is up.",
                      "Look at its CPU and logs if it is overloaded."]),
    "Internet by IP": ("past the gateway: the router's internet side, a firewall or the ISP",
                       "The LAN is healthy up to the gateway, but nothing beyond it answers.",
                       ["Check the WAN link and public IP on the router or firewall.",
                        "Check for an ISP outage or an outbound deny rule.",
                        "Use the path trace to see the exact hop where packets stop."]),
    "TCP egress": ("an outbound firewall or proxy policy",
                   "Ping gets out but TCP 443 does not, so something is filtering by port.",
                   ["Check firewall egress rules and any required web proxy.",
                    W("Check the host firewall: sudo iptables -L -n or sudo nft list ruleset.", "Check Windows Defender Firewall outbound rules (wf.msc).")]),
    "MTU / fragmentation": ("an MTU mismatch on the path",
                            "Full-size packets are being dropped.",
                            ["Common with VPNs, PPPoE and tunnels.",
                             "Lower the interface MTU to the exact value found, or enable TCP MSS clamping (MTU minus 40) on the router."]),
    "DNS servers": ("DNS",
                    "None of the configured DNS servers gave a usable answer.",
                    ["Check the DNS server or forwarder is running.",
                     W("Test a public resolver: dig @1.1.1.1 google.com.", "Test a public resolver: nslookup google.com 1.1.1.1"),
                     "Check UDP/TCP 53 is allowed outbound."]),
    "Name resolution": ("name lookups on this machine",
                        "The internet works by IP, but names do not resolve.",
                        [W("Check /etc/resolv.conf and systemd-resolved: resolvectl status.",
                           "Run ipconfig /flushdns, then check the adapter's DNS servers with ipconfig /all."),
                         W("Try a public resolver to confirm: dig @1.1.1.1 google.com.",
                           "Try a public resolver to confirm: nslookup google.com 1.1.1.1")]),
    "HTTPS": ("web access, TLS or a proxy",
              "Basic connectivity is fine but HTTPS requests fail.",
              ["If the error mentions certificates, check the system clock and any SSL inspection.",
               "Check proxy settings (http_proxy / https_proxy)."]),
    "Captive portal / proxy": ("a captive portal or transparent proxy",
                               "Plain web requests are being intercepted.",
                               ["Open a browser and complete the portal login.",
                                "Check for a transparent proxy on the network."]),
    "Line quality": ("connection quality",
                     "The connection works but performance is poor.",
                     ["Run the path trace to see where loss or latency starts.",
                      "Check for saturation in the Live traffic panel.",
                      "On Wi-Fi, check signal and channel congestion."]),
}


def C(name, status, detail, fix=""):
    return {"layer": LAYER[name], "name": name, "status": status, "detail": detail,
            "rules_out": RULES_OUT[name], "fix": fix}


def health():
    gw, dev, iface, ifs, rt = primary()
    dns = dns_info()
    gw_ip = gw["gateway"] if gw else None
    targets = ["1.1.1.1", "8.8.8.8"]
    names = ["google.com", "cloudflare.com"]
    servers = list(dict.fromkeys(dns["resolv_conf"] + dns["upstream"]))

    ex = cf.ThreadPoolExecutor(max_workers=20)
    fut = {}
    if gw_ip:
        fut["gw"] = ex.submit(ping, gw_ip, 4)
    for t in targets:
        fut["net_" + t] = ex.submit(ping, t, 10)
    for t in targets:
        fut["tcp_" + t] = ex.submit(tcp_probe, t, 443)
    for s in servers:
        fut["dns_" + s] = ex.submit(dns_probe, s, names[0])
    for nm in names:
        fut["sys_" + nm] = ex.submit(sys_resolve, nm)
    fut["https"] = ex.submit(http_probe, "https://www.google.com/generate_204")
    fut["portal"] = ex.submit(http_probe, "http://connectivitycheck.gstatic.com/generate_204")
    fut["pubip"] = ex.submit(public_ip)

    def get(k, t=25):
        try:
            return fut[k].result(timeout=t)
        except Exception:  # noqa: BLE001
            return None

    res = {}
    # L1 physical
    if not iface:
        res["Physical link"] = C("Physical link", "fail",
                                 "No usable interface (nothing has an address or a default route).",
                                 "Check the cable or the Wi-Fi connection.")
    else:
        up = iface["state"] in ("UP", "UNKNOWN") and iface["carrier"] in ("1", None) and iface["state"] != "DOWN"
        if iface["carrier"] == "0":
            up = False
        bits, warn = [f"{iface['name']} is {iface['state']}"], []
        if iface["wireless"]:
            w = iface.get("wifi") or {}
            if w.get("ssid"):
                bits.append(f"Wi-Fi '{w['ssid']}' at {w.get('signal', '?')} dBm, {w.get('bitrate', '?')}")
            if isinstance(w.get("signal"), int) and w["signal"] <= -75:
                warn.append(f"weak signal ({w['signal']} dBm)")
        elif iface["speed"]:
            bits.append(f"{iface['speed']} Mb/s {iface['duplex'] or ''}".strip())
            if not iface["virtual"] and iface["speed"] < 1000:
                warn.append(f"only {iface['speed']} Mb/s negotiated (bad cable or port?)")
            if iface["duplex"] == "half":
                warn.append("half duplex (possible duplex mismatch)")
        errs = (iface["rx_errors"] or 0) + (iface["tx_errors"] or 0)
        if errs:
            warn.append(f"{errs} interface errors (CRC/frame errors point to cabling, NIC or switch port)")
        if not up:
            res["Physical link"] = C("Physical link", "fail",
                                     f"{iface['name']} has no link (state {iface['state']}, carrier {iface['carrier'] or '0'}).",
                                     "Reseat the cable, try another port, or reconnect Wi-Fi.")
        else:
            res["Physical link"] = C("Physical link", "warn" if warn else "pass", "; ".join(bits + warn),
                                     "Replace the patch cable and check the switch port counters." if warn else "")
    # L3 addressing
    v4 = iface["ipv4"] if iface else []
    if not v4:
        res["IP address"] = C("IP address", "fail", "No IPv4 address. DHCP did not answer.",
                              "Check the DHCP server and the VLAN on the switch port.")
    elif all(a.startswith("169.254.") for a in v4):
        res["IP address"] = C("IP address", "fail", f"Only a self-assigned address ({v4[0]}). The DHCP server never replied.",
                              "Check the DHCP server, scope and VLAN.")
    else:
        res["IP address"] = C("IP address", "pass", f"{iface['name']} has {', '.join(v4)}")
    # default route
    if gw_ip:
        res["Default route"] = C("Default route", "pass", f"Default route via {gw_ip} on {dev}")
    else:
        res["Default route"] = C("Default route", "fail", "No default route. Only the local subnet is reachable.",
                                 W("Check DHCP option 3 or add: sudo ip route add default via <gw>", "Check DHCP option 3 or the adapter's gateway setting."))
    # gateway
    if gw_ip:
        gp = get("gw")
        arp_ok, arp_detail = gateway_arp(gw_ip, dev)
        res["Gateway ARP"] = C("Gateway ARP", "pass" if arp_ok else "fail", arp_detail,
                               "" if arp_ok else "Check VLAN, subnet mask and switch port security.")
        if gp and gp["loss"] < 100:
            res["Gateway ping"] = C("Gateway ping", "pass" if gp["loss"] == 0 else "warn",
                                    f"{gp['loss']:.0f}% loss, avg {gp['avg']} ms to {gw_ip}",
                                    "" if gp["loss"] == 0 else "Loss on the LAN: check cabling, Wi-Fi signal or a busy gateway.")
        elif arp_ok:
            res["Gateway ping"] = C("Gateway ping", "warn",
                                    "Gateway answers ARP but ignores ping. Many firewalls do this, so it is not a fault by itself.")
        else:
            res["Gateway ping"] = C("Gateway ping", "fail", f"Gateway {gw_ip} answers neither ping nor ARP.",
                                    "Check the gateway is up.")
    else:
        for n in ("Gateway ARP", "Gateway ping"):
            res[n] = C(n, "skip", "Not tested: there is no default gateway.")
    # internet by IP and TCP egress
    nets = {t: get("net_" + t) for t in targets}
    reach = [t for t, p in nets.items() if p and p["loss"] < 100]
    tcp = [get("tcp_" + t) for t in targets]
    tcp_ok = [x for x in tcp if x and x["ok"]]
    if reach:
        detail = ", ".join(f"{t}: {nets[t]['loss']:.0f}% loss, {nets[t]['avg']} ms" if t in reach else f"{t}: no reply"
                           for t in targets)
        clean = len(reach) == len(targets) and all(nets[t]["loss"] == 0 for t in reach)
        res["Internet by IP"] = C("Internet by IP", "pass" if clean else "warn", detail,
                                  "" if clean else "Some loss upstream. Run the path trace.")
    elif tcp_ok:
        res["Internet by IP"] = C("Internet by IP", "warn",
                                  "Ping to the internet is blocked but TCP works. ICMP is filtered upstream, not a real outage.")
    else:
        res["Internet by IP"] = C("Internet by IP", "fail",
                                  "No reply from 1.1.1.1 or 8.8.8.8 by ping or TCP. Traffic stops at or after the gateway.",
                                  "Check the router WAN link, ISP status and the path trace.")
    if tcp_ok:
        res["TCP egress"] = C("TCP egress", "pass", ", ".join(f"{x['host']}:443 connected in {x['ms']} ms" for x in tcp_ok))
    else:
        res["TCP egress"] = C("TCP egress", "fail",
                              "Ping gets out but TCP 443 is blocked. A firewall or proxy is filtering by port." if reach
                              else "TCP 443 to 1.1.1.1 and 8.8.8.8 also failed.",
                              "Check firewall egress rules and proxy requirements.")
    # MTU
    if reach:
        mt = mtu_probe(reach[0], iface["mtu"] if iface else None)
        im = mt["iface_mtu"]
        if mt["full"]:
            note = "" if im == 1500 else f" (this interface is set to MTU {im}, so that is the largest it sends)"
            res["MTU / fragmentation"] = C("MTU / fragmentation", "pass",
                                           f"Full {im}-byte packets reach {reach[0]} without fragmenting{note}.")
        elif mt["mtu"] and mt["pmtud"]:
            res["MTU / fragmentation"] = C("MTU / fragmentation", "pass",
                                           f"Path MTU to {reach[0]} is {mt['mtu']} bytes (interface is {im}). "
                                           f"A router on the path reports this correctly (\"fragmentation needed\", mtu {mt['reported']}), "
                                           "so TCP adjusts on its own. Normal for PPPoE (1492), VPNs and tunnels; nothing to fix.")
        elif mt["mtu"]:
            m, mss = mt["mtu"], mt["mtu"] - 40
            res["MTU / fragmentation"] = C("MTU / fragmentation", "warn",
                                           f"Path MTU to {reach[0]} is exactly {m} bytes but this interface sends {im}, and nothing on the path "
                                           "reports the limit, so oversized packets vanish (an MTU black hole). Symptoms: pages that half-load, "
                                           "stalled downloads, SSH/VPN sessions that freeze on large output.",
                                           W(f"Test now: sudo ip link set dev {dev} mtu {m}. If that fixes it, make it permanent with "
                                             f"nmcli con mod \"<connection>\" 802-3-ethernet.mtu {m} (use 802-11-wireless.mtu on Wi-Fi), "
                                             f"or better, enable TCP MSS clamping to {mss} on the router so every device is fixed.",
                                             f"Test now (as administrator): netsh interface ipv4 set subinterface \"{dev}\" mtu={m} store=active. "
                                             f"If that fixes it, run it again with store=persistent, or better, enable TCP MSS clamping "
                                             f"to {mss} on the router so every device is fixed."))
        else:
            res["MTU / fragmentation"] = C("MTU / fragmentation", "warn",
                                           f"Don't-fragment pings to {reach[0]} fail at every size while normal pings work. "
                                           "Something on the path is dropping DF packets.",
                                           "Check firewall rules that drop fragmented or DF packets.")
    else:
        res["MTU / fragmentation"] = C("MTU / fragmentation", "skip", "Not tested: the internet is not reachable by ping.")
    # DNS servers
    if not servers:
        res["DNS servers"] = C("DNS servers", "fail", "No DNS servers configured in /etc/resolv.conf.",
                               W("Set DNS via DHCP, NetworkManager or resolv.conf.", "Set DNS servers in the adapter settings or via DHCP."))
    else:
        results = [(s, get("dns_" + s)) for s in servers]
        good = [s for s, r in results if r and r["ok"]]
        detail = "; ".join(f"{s}: OK {r['ms']} ms" if r and r["ok"] else f"{s}: FAILED ({(r or {}).get('err', 'timeout')})"
                           for s, r in results)
        st = "pass" if len(good) == len(servers) else "warn" if good else "fail"
        res["DNS servers"] = C("DNS servers", st, detail,
                               "" if st == "pass" else "Remove or fix the failing DNS server.")
    # system resolution
    sr = {nm: get("sys_" + nm, 15) for nm in names}
    ok = [nm for nm, r in sr.items() if r and r["ok"]]
    detail = "; ".join(f"{nm} resolved to {r['ip']} in {r['ms']} ms" if r and r["ok"]
                       else f"{nm}: {(r or {}).get('err', 'timed out')}" for nm, r in sr.items())
    if ok:
        slow = max(sr[nm]["ms"] for nm in ok)
        res["Name resolution"] = C("Name resolution", "warn" if slow > 500 else "pass",
                                   detail + (" (slow DNS)" if slow > 500 else ""),
                                   "DNS is slow: try a closer or faster resolver." if slow > 500 else "")
    else:
        res["Name resolution"] = C("Name resolution", "fail", detail,
                                   W("Check resolv.conf / resolvectl status, or test dig @1.1.1.1 google.com", "Run ipconfig /flushdns, or test nslookup google.com 1.1.1.1"))
    # HTTPS
    h = get("https")
    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    if h and h["ok"] and h["code"] == 204:
        res["HTTPS"] = C("HTTPS", "pass", f"HTTPS request succeeded in {h['ms']} ms" + (f" via proxy {proxy}" if proxy else ""))
    elif h and h["ok"]:
        res["HTTPS"] = C("HTTPS", "warn", f"HTTPS answered with HTTP {h['code']} instead of 204. Something is in the way.",
                         "Check for a proxy or captive portal.")
    else:
        err = (h or {}).get("err", "timed out")
        hint = ("Certificate not trusted: SSL inspection, a captive portal, or a wrong system clock."
                if "CERTIFICATE" in err.upper() else "Check proxy settings and outbound 443.")
        res["HTTPS"] = C("HTTPS", "fail", f"HTTPS request failed: {err}", hint)
    # captive portal
    p = get("portal")
    url = "http://connectivitycheck.gstatic.com/generate_204"
    if p and p["ok"] and p["code"] == 204 and p.get("final", url) == url:
        res["Captive portal / proxy"] = C("Captive portal / proxy", "pass", "Plain HTTP is not being intercepted.")
    elif p and p["ok"]:
        where = f", redirected to {p['final']}" if p.get("final") and p["final"] != url else ""
        res["Captive portal / proxy"] = C("Captive portal / proxy", "warn",
                                          f"Plain HTTP got {p['code']}{where}. A captive portal or proxy is intercepting web traffic.",
                                          "Open a browser and complete the portal login, or check the proxy.")
    else:
        res["Captive portal / proxy"] = C("Captive portal / proxy", "warn" if (h and h["ok"]) else "fail",
                                          f"Plain HTTP (port 80) failed: {(p or {}).get('err', 'timed out')}",
                                          "Port 80 may be blocked outbound.")
    # quality
    q = nets.get(reach[0]) if reach else None
    if q:
        issues = []
        if q["loss"] > 0:
            issues.append(f"{q['loss']:.0f}% packet loss")
        if q["avg"] and q["avg"] > 150:
            issues.append(f"high latency ({q['avg']} ms)")
        if q["mdev"] and q["mdev"] > 30:
            issues.append(f"high jitter ({q['mdev']} ms)")
        detail = f"{q['loss']:.0f}% loss, {q['avg']} ms average, {q['mdev']} ms jitter over 10 pings to {reach[0]}"
        res["Line quality"] = C("Line quality", "warn" if issues else "pass",
                                detail + (": " + ", ".join(issues) if issues else ""),
                                "Run the path trace and watch Live traffic for saturation." if issues else "")
    else:
        res["Line quality"] = C("Line quality", "skip", "Not tested: no ping replies from the internet.")

    checks = [res[n] for n in ORDER if n in res]
    out = {"time": now(), "interface": dev, "gateway": gw_ip, "checks": checks,
           "verdict": verdict(checks), "public_ip": get("pubip", 8)}
    ex.shutdown(wait=False)
    return remember("health", out)


def verdict(checks):
    fails = [c for c in checks if c["status"] == "fail"]
    warns = [c for c in checks if c["status"] == "warn"]
    if fails:
        f = fails[0]
        dom, expl, steps = DOMAIN[f["name"]]
        idx = ORDER.index(f["name"])
        ruled = [c["rules_out"] for c in checks if c["status"] == "pass" and ORDER.index(c["name"]) < idx]
        detail = f"{expl} {f['detail']}"
        if len(fails) > 1:
            detail += f" {len(fails) - 1} later check(s) also failed, most likely as a knock-on effect of this one."
        return {"status": "fail", "headline": f"The problem is {dom}.", "detail": detail,
                "ruled_out": ruled, "suspects": [f["name"]], "next": steps}
    ruled = [c["rules_out"] for c in checks if c["status"] == "pass"]
    if warns:
        return {"status": "warn", "headline": "Everything connects, but something needs a look.",
                "detail": "Everything is reachable end to end. Flagged: " +
                          "; ".join(f"{w['name']}: {w['detail']}" for w in warns),
                "ruled_out": ruled, "suspects": [w["name"] for w in warns],
                "next": [w["fix"] for w in warns if w["fix"]]}
    return {"status": "pass", "headline": "Your network is healthy end to end.",
            "detail": "Link, addressing, gateway, internet, DNS and HTTPS all check out from this machine. "
                      "If an app or site still fails, look at the remote server, the application itself, "
                      "or a firewall on this host. Trace the path to that specific server below.",
            "ruled_out": ruled, "suspects": [], "next": []}



# --------------------------------------------------------------------------
# apps: every program with a network socket, its PIDs and live speed
# --------------------------------------------------------------------------
APP_NAMES = {
    "brave": "Brave", "brave-browser": "Brave", "chrome": "Google Chrome", "google-chrome": "Google Chrome",
    "chromium": "Chromium", "chromium-browse": "Chromium", "msedge": "Microsoft Edge", "firefox": "Firefox",
    "firefox-bin": "Firefox", "socket process": "Firefox", "isolated web co": "Firefox", "code": "VS Code",
    "spotify": "Spotify", "discord": "Discord", "slack": "Slack", "steam": "Steam", "telegram-deskto": "Telegram",
    "thunderbird": "Thunderbird", "zoom": "Zoom", "teams": "Microsoft Teams", "sshd": "SSH server", "ssh": "SSH client",
    "systemd-resolve": "systemd-resolved (DNS)", "networkmanager": "NetworkManager", "avahi-daemon": "Avahi (mDNS)",
    "cupsd": "CUPS printing", "cups-browsed": "CUPS printing", "dhclient": "DHCP client", "chronyd": "Chrony (time)",
    "systemd-timesyn": "Time sync", "snapd": "Snap store", "packagekitd": "Software updates", "dnsmasq": "dnsmasq",
    "vmtoolsd": "VMware Tools", "tailscaled": "Tailscale", "openvpn": "OpenVPN", "wireguard": "WireGuard",
    "transmission-gt": "Transmission", "qbittorrent": "qBittorrent", "vlc": "VLC", "obs": "OBS Studio",
}
_REV = {}
_REV_LOCK = threading.Lock()
_REV_POOL = cf.ThreadPoolExecutor(8)
_APPS_PREV = {}
_NETHOGS = {"rates": {}, "at": 0, "proc": None, "started": False}
_PROC_CACHE = {}


def rev_name(ip):
    """Reverse DNS without blocking: returns a cached name, or '' and resolves in the background."""
    ip = ip.strip("[]")
    try:
        a = ipaddress.ip_address(ip)
        if a.is_loopback or a.is_unspecified or a.is_multicast:
            return ""
    except ValueError:
        return ""
    with _REV_LOCK:
        if ip in _REV:
            return _REV[ip] or ""
        _REV[ip] = None

    def work():
        name = resolve_dns_only(ip)
        with _REV_LOCK:
            _REV[ip] = name
    _REV_POOL.submit(work)
    return ""


def proc_info(pid):
    """Name, role, user and command line of a process (Linux /proc, or psutil on Windows)."""
    key = (pid, int(time.time() // 30))
    if key in _PROC_CACHE:
        return _PROC_CACHE[key]
    info = {"pid": pid, "comm": "", "cmd": "", "exe": "", "user": "", "role": ""}
    if IS_WIN and psutil:
        try:
            p = psutil.Process(int(pid))
            info.update(comm=p.name(), exe=p.exe() or "", cmd=" ".join(p.cmdline())[:400])
            info["user"] = (p.username() or "").split("\\")[-1]
        except Exception:  # noqa: BLE001
            pass
    else:
        base = f"/proc/{pid}"
        info["comm"] = read(f"{base}/comm", "") or ""
        try:
            with open(f"{base}/cmdline", "rb") as f:
                info["cmd"] = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()[:400]
        except OSError:
            pass
        try:
            info["exe"] = os.readlink(f"{base}/exe")
        except OSError:
            pass
        m = re.search(r"^Uid:\s+(\d+)", read(f"{base}/status", "") or "", re.M)
        if m:
            try:
                import pwd
                info["user"] = pwd.getpwuid(int(m.group(1))).pw_name
            except Exception:  # noqa: BLE001
                info["user"] = m.group(1)
    t = re.search(r"--type=(\S+)", info["cmd"])
    sub = re.search(r"--utility-sub-type=(\S+)", info["cmd"])
    if sub and "network" in sub.group(1).lower():
        info["role"] = "network service"
    elif t:
        info["role"] = t.group(1).replace("-", " ")
    elif pid == os.getpid():
        info["role"] = "this app"
    comm = info["comm"] or os.path.basename(info["exe"]) or "?"
    stem = re.sub(r"\.exe$", "", comm, flags=re.I).lower()
    info["app"] = "NetPane" if pid == os.getpid() else APP_NAMES.get(stem, comm)
    if len(_PROC_CACHE) > 4000:
        _PROC_CACHE.clear()
    _PROC_CACHE[key] = info
    return info


def _nethogs_loop():
    """Run nethogs in trace mode and keep the latest per-PID rates (KB/s) in memory."""
    try:
        # -C counts UDP too (QUIC). stdbuf stops nethogs holding its output back when piped.
        cmd = [which("nethogs"), "-t", "-C", "-d", "1"]
        if have("stdbuf"):
            cmd = [which("stdbuf"), "-oL"] + cmd
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, errors="replace", env=ENV)
    except OSError:
        return
    _NETHOGS["proc"] = p
    cur = {}
    for line in p.stdout:
        line = line.rstrip("\n")
        if line.startswith("Refreshing"):
            _NETHOGS.update(rates=cur, at=time.time())
            cur = {}
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        ident = parts[0].rsplit("/", 2)
        if len(ident) != 3 or not ident[1].isdigit() or ident[1] == "0":
            continue
        try:
            sent, recv = float(parts[1]), float(parts[2])
        except ValueError:
            continue
        pid = int(ident[1])
        s0, r0 = cur.get(pid, (0.0, 0.0))
        cur[pid] = (s0 + sent * 1024, r0 + recv * 1024)


def _start_nethogs():
    if _NETHOGS["started"] or IS_WIN or not IS_ROOT or not have("nethogs"):
        return
    _NETHOGS["started"] = True
    threading.Thread(target=_nethogs_loop, daemon=True).start()


def _socket_rows_linux():
    """ss -tunapi: every TCP/UDP socket with all owning PIDs and TCP byte counters."""
    rows, cur = [], None
    for line in run(["ss", "-H", "-tunapi"], 10)["out"].splitlines():
        if line[:1] in ("\t", " ") and cur is not None:
            m1 = re.search(r"\bbytes_received:(\d+)", line)
            m2 = re.search(r"\bbytes_acked:(\d+)", line)
            if m1:
                cur["rx"] = int(m1.group(1))
            if m2:
                cur["tx"] = int(m2.group(1))
            continue
        p = line.split()
        if len(p) < 6:
            cur = None
            continue
        rest = " ".join(p[6:])
        pids = [int(x) for x in re.findall(r"pid=(\d+)", rest)]
        cur = {"proto": p[0], "state": p[1], "local": p[4], "peer": p[5], "pids": sorted(set(pids)), "rx": None, "tx": None}
        rows.append(cur)
    return rows


def _socket_rows_win():
    out = []
    for r in win_socket_rows():
        out.append({"proto": r["proto"], "state": r["state"], "local": r["local"], "peer": r["peer"],
                    "pids": [int(r["pid"])] if r["pid"] and r["pid"] != "0" else [], "rx": None, "tx": None})
    return out


def _host_of(addr):
    return addr.rsplit(":", 1)[0].strip("[]").split("%")[0]


def apps():
    _start_nethogs()
    rows = _socket_rows_win() if IS_WIN else _socket_rows_linux()
    now_t = time.time()
    # per-socket TCP rates from the change in byte counters since the last call
    seen = {}
    for r in rows:
        if r["rx"] is None:
            continue
        key = (r["proto"], r["local"], r["peer"])
        seen[key] = (now_t, r["rx"], r["tx"] or 0)
        prev = _APPS_PREV.get(key)
        if prev and now_t - prev[0] > 0.2:
            dt = now_t - prev[0]
            r["rx_rate"] = max(0.0, (r["rx"] - prev[1]) / dt)
            r["tx_rate"] = max(0.0, ((r["tx"] or 0) - prev[2]) / dt)
    _APPS_PREV.clear()
    _APPS_PREV.update(seen)

    hogs = _NETHOGS["rates"] if now_t - _NETHOGS["at"] < 6 else {}
    rate_source = "nethogs" if _NETHOGS["started"] and hogs is not None and _NETHOGS["at"] else ("none" if IS_WIN else "tcp")

    procs = {}
    unowned = 0
    for r in rows:
        if not r["pids"]:
            unowned += 1
            continue
        share = len(r["pids"])
        for pid in r["pids"]:
            pr = procs.get(pid)
            if pr is None:
                info = proc_info(pid)
                pr = procs[pid] = dict(info, sockets=[], conns=0, listening=[], udp=0, rx_rate=0.0, tx_rate=0.0,
                                      rx_total=0, tx_total=0, peers=collections.Counter())
            peer_ip = _host_of(r["peer"])
            pr["sockets"].append({"proto": r["proto"], "state": r["state"], "local": r["local"], "peer": r["peer"],
                                  "peer_name": rev_name(peer_ip) if r["state"] == "ESTAB" else "",
                                  "rx": r["rx"], "tx": r["tx"]})
            if r["state"] == "ESTAB":
                pr["conns"] += 1
                pr["peers"][peer_ip] += 1
            elif r["state"] == "LISTEN" or (r["proto"] == "udp" and r["state"] == "UNCONN"):
                port = r["local"].rsplit(":", 1)[-1]
                if r["state"] == "LISTEN":
                    pr["listening"].append(f"{port}/tcp")
                else:
                    pr["udp"] += 1
            pr["rx_rate"] += r.get("rx_rate", 0.0) / share
            pr["tx_rate"] += r.get("tx_rate", 0.0) / share
            pr["rx_total"] += (r["rx"] or 0) // share
            pr["tx_total"] += (r["tx"] or 0) // share
    if rate_source == "nethogs":
        # TCP counters are exact and instant; nethogs adds UDP/QUIC but averages over ~5 s. Take the higher.
        for pid, (sent, recv) in hogs.items():
            if pid in procs:
                procs[pid]["tx_rate"] = max(procs[pid]["tx_rate"], sent)
                procs[pid]["rx_rate"] = max(procs[pid]["rx_rate"], recv)

    out = []
    for pr in procs.values():
        top = [{"ip": ip, "name": rev_name(ip), "count": c} for ip, c in pr["peers"].most_common(5)]
        pr["listening"] = sorted(set(pr["listening"]), key=lambda x: int(x.split("/")[0]) if x.split("/")[0].isdigit() else 0)
        pr.pop("peers")
        pr["top_peers"] = top
        pr["sockets"].sort(key=lambda s: (s["state"] != "ESTAB", s["peer"]))
        out.append(pr)
    out.sort(key=lambda p: (-(p["rx_rate"] + p["tx_rate"]), -p["conns"], p["app"].lower()))
    if rate_source == "nethogs":
        note = ("Live speeds combine the kernel's TCP counters with nethogs, so UDP and QUIC traffic is included. "
                "UDP-only bursts take a few seconds to show at full speed.")
    elif IS_WIN:
        note = "Live speeds per app aren't available on Windows yet. Connection counts and PIDs are exact."
    else:
        bits = ["Live speeds count TCP only, from the kernel's per-connection byte counters."
                " Browsers send some traffic (YouTube, Google) over QUIC, which is UDP, so they may read low."]
        if not have("nethogs"):
            bits.append("Install nethogs and start NetPane with sudo to include UDP: sudo apt install nethogs")
        elif not IS_ROOT:
            bits.append("Start NetPane with sudo to switch to nethogs, which includes UDP.")
        note = " ".join(bits)
    hidden = "" if IS_ROOT else W(
        "Not running as root, so only your own programs are listed. Start with sudo to see system services too.",
        "Not running as administrator, so a few system programs may be missing.")
    return {"time": now(), "apps": out, "rate_source": rate_source, "note": note, "hidden": hidden,
            "unowned": unowned, "total_sockets": len(rows)}


# --------------------------------------------------------------------------
# path trace, sockets, wifi, traffic
# --------------------------------------------------------------------------
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]{0,252}$")


def path(target):
    if not HOST_RE.match(target or ""):
        return {"error": "Invalid target", "hops": []}
    hops, method = [], ""
    if IS_WIN:
        hops = parse_tracert(run(["tracert", "-d", "-w", "1000", "-h", "20", target], 90)["out"])
        method = "tracert"
    elif have("mtr"):
        j = run_json(["mtr", "--json", "-n", "-c", "5", target], 60)
        try:
            for h in j["report"]["hubs"]:
                hops.append({"hop": h.get("count"), "host": h.get("host"), "loss": round(float(h.get("Loss%", 0)), 1),
                             "avg": h.get("Avg"), "best": h.get("Best"), "worst": h.get("Wrst")})
            method = "mtr, 5 cycles"
        except Exception:  # noqa: BLE001
            hops = []
    if not hops and have("traceroute"):
        r = run(["traceroute", "-n", "-q", "3", "-w", "1", "-m", "20", target], 70)
        for line in r["out"].splitlines()[1:]:
            m = re.match(r"\s*(\d+)\s+(.*)", line)
            if not m:
                continue
            rest = m.group(2)
            ips = re.findall(r"\d+\.\d+\.\d+\.\d+|[0-9a-fA-F]*:[0-9a-fA-F:]+", rest)
            times = [float(x) for x in re.findall(r"([\d.]+) ms", rest)]
            stars = rest.count("*")
            sent = (len(times) + stars) or 3
            hops.append({"hop": int(m.group(1)), "host": ips[0] if ips else "???",
                         "loss": round(100 * stars / sent), "avg": round(sum(times) / len(times), 1) if times else None,
                         "best": min(times) if times else None, "worst": max(times) if times else None})
        method = "traceroute"
    if not hops and have("tracepath"):
        r = run(["tracepath", "-n", "-m", "20", target], 70)
        seen = set()
        for line in r["out"].splitlines():
            m = re.match(r"\s*(\d+)\??:\s+(\S+)(?:\s+([\d.]+)ms)?", line)
            if m and int(m.group(1)) not in seen and m.group(2) != "[LOCALHOST]":
                n = int(m.group(1))
                seen.add(n)
                t = float(m.group(3)) if m.group(3) else None
                hops.append({"hop": n, "host": "???" if m.group(2) == "no" else m.group(2),
                             "loss": 0 if t is not None else 100, "avg": t, "best": t, "worst": t})
        method = "tracepath"
    if not hops:
        return remember("path", {"target": target, "error": W("No path tool worked here. Install mtr or traceroute.", "tracert returned nothing."), "hops": []})
    try:
        dest = socket.gethostbyname(target)
    except OSError:
        dest = target
    ex = cf.ThreadPoolExecutor(16)
    futs = {h["host"]: ex.submit(resolve_dns_only, h["host"]) for h in hops if h["host"] and h["host"] != "???"}
    for h in hops:
        f = futs.get(h["host"])
        try:
            h["name"] = f.result(timeout=3) if f else ""
        except Exception:  # noqa: BLE001
            h["name"] = ""
    ex.shutdown(wait=False)
    reached = any(h["host"] == dest and (h["loss"] or 0) < 100 for h in hops)
    return remember("path", {"target": target, "dest_ip": dest, "method": method, "hops": hops,
                             "reached": reached, "time": now()})


def resolve_dns_only(ip):
    try:
        n = socket.gethostbyaddr(ip)[0]
        return "" if n == ip else n
    except Exception:  # noqa: BLE001
        return ""


def sockets():
    r = {"ok": True, "out": "", "err": ""} if IS_WIN else run(["ss", "-H", "-tunap"], 10)
    rows = win_socket_rows() if IS_WIN else []
    for line in r["out"].splitlines():
        p = line.split()
        if len(p) < 6:
            continue
        m = re.search(r'\(\("([^"]+)",pid=(\d+)', " ".join(p[6:]))
        rows.append({"proto": p[0], "state": p[1], "local": p[4], "peer": p[5],
                     "process": m.group(1) if m else "", "pid": m.group(2) if m else ""})

    def port_of(x):
        try:
            return int(x["local"].rsplit(":", 1)[1])
        except (ValueError, IndexError):
            return 0
    listening = sorted([x for x in rows if x["state"] in ("LISTEN", "UNCONN")], key=port_of)
    established = [x for x in rows if x["state"] == "ESTAB"]
    note = "" if IS_ROOT else W("Not running as root, so process names for other users' sockets are hidden.",
                                "Not running as administrator, so some program names may be missing.")
    if not rows and not r["ok"]:
        note = r["err"]
    return remember("sockets", {"all": rows[:3000], "listening": listening, "established": established[:1500], "note": note})


def wifi_scan():
    if IS_WIN:
        return remember("wifi", wifi_scan_win())
    nets, note = [], ""
    if have("nmcli"):
        r = run(["nmcli", "-t", "-f", "IN-USE,SSID,CHAN,SIGNAL,SECURITY", "device", "wifi", "list"], 15)
        for line in r["out"].splitlines():
            f = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
            if len(f) >= 5:
                try:
                    sig = int(f[3])
                except ValueError:
                    sig = 0
                nets.append({"inuse": f[0].strip() == "*", "ssid": f[1], "chan": f[2], "signal": sig,
                             "security": f[4] or "open"})
        nets.sort(key=lambda n: -n["signal"])
        if not r["ok"]:
            note = r["err"].strip()
    else:
        note = "Install network-manager (nmcli) to list nearby Wi-Fi networks."
    return remember("wifi", {"networks": nets, "note": note})


def read_netdev():
    if IS_WIN:
        if psutil is None:
            return {}
        return {k: (v.bytes_recv, v.bytes_sent) for k, v in psutil.net_io_counters(pernic=True).items()}
    data = {}
    for line in (read("/proc/net/dev", "") or "").splitlines()[2:]:
        name, _, rest = line.partition(":")
        f = rest.split()
        if len(f) >= 9:
            data[name.strip()] = (int(f[0]), int(f[8]))
    return data


def sampler():
    prev, pt = read_netdev(), time.time()
    while True:
        time.sleep(1)
        cur, t = read_netdev(), time.time()
        span = max(t - pt, 0.001)
        with STATE_LOCK:
            for k, (rx, tx) in cur.items():
                if k in prev:
                    TRAFFIC[k].append([round(t, 1), max(0.0, (rx - prev[k][0]) / span), max(0.0, (tx - prev[k][1]) / span)])
        prev, pt = cur, t


def traffic():
    with STATE_LOCK:
        return {k: list(v) for k, v in TRAFFIC.items() if k != "lo" and not k.lower().startswith("loopback")}


# --------------------------------------------------------------------------
# console: run any of the tools with safe bounds
# --------------------------------------------------------------------------
CONSOLE_TIMEOUT = {"tracert": 120, "pathping": 300, "nmap": 180, "traceroute": 90, "mtr": 90, "tcpdump": 60, "tshark": 60, "ngrep": 60,
                   "iperf3": 60, "whois": 30, "lshw": 60}


def _has(args, *flags):
    for a in args:
        for f in flags:
            if a == f or (len(f) == 2 and a.startswith(f) and not a.startswith("--")):
                return True
    return False


def guard_win(tool, a):
    low = [x.lower() for x in a]
    if tool == "ping":
        a = [x for x in a if x.lower() not in ("-t", "/t")]
        if not any(x in ("-n", "/n") for x in low):
            a = ["-n", "4"] + a
    elif tool == "tracert":
        if not any(x in ("-h", "/h") for x in low):
            a = ["-h", "20"] + a
        if not any(x in ("-w", "/w") for x in low):
            a = ["-w", "1000"] + a
    elif tool == "pathping" and not any(x in ("-q", "/q") for x in low):
        a = ["-q", "10"] + a
    elif tool == "netstat":
        a = [x for x in a if not x.isdigit()]
    elif tool == "tshark" and not _has(a, "-c", "-a") and "-D" not in a:
        a = ["-c", "50"] + a
    elif tool == "iperf3":
        if "-s" in a and not _has(a, "-1"):
            a.append("-1")
        if _has(a, "-c") and not _has(a, "-t"):
            a += ["-t", "5"]
    elif tool in ("nslookup", "netsh") and not a:
        return None, f"{tool} needs arguments here, or it waits for typed input. Try one of the examples."
    return a, None


def guard(tool, a):
    a = list(a)
    if IS_WIN:
        return guard_win(tool, a)
    if tool in ("ping", "arping", "hping3") and not _has(a, "-c"):
        a = ["-c", "4"] + a
    elif tool == "fping":
        a = [x for x in a if x not in ("-l", "--loop")]
    elif tool == "mtr":
        if not _has(a, "-r") and "--report" not in a and "--json" not in a:
            a = ["-r"] + a
        if not _has(a, "-c"):
            a = ["-c", "5"] + a
    elif tool == "tcpdump":
        if not _has(a, "-c"):
            a = ["-c", "50"] + a
        if not _has(a, "-l"):
            a = ["-l"] + a
    elif tool == "tshark" and not _has(a, "-c", "-a"):
        a = ["-c", "50"] + a
    elif tool == "ngrep" and not _has(a, "-n"):
        a = ["-n", "30"] + a
    elif tool == "iftop":
        if not _has(a, "-t"):
            a = ["-t"] + a
        if not _has(a, "-s"):
            a = ["-s", "5"] + a
    elif tool == "nethogs":
        if not _has(a, "-t"):
            a = ["-t"] + a
        if not _has(a, "-c"):
            a = ["-c", "5"] + a
    elif tool == "nload":
        return None, "nload is full-screen only and can't run here. The Live traffic panel on the dashboard shows the same thing."
    elif tool == "iperf3":
        if "-s" in a and not _has(a, "-1"):
            a.append("-1")
        if _has(a, "-c") and not _has(a, "-t"):
            a += ["-t", "5"]
    elif tool == "vnstat" and (_has(a, "-l") or "--live" in a):
        return None, "vnstat live mode runs forever. Use the Live traffic panel instead."
    elif tool == "lshw" and not a:
        a = ["-class", "network", "-short"]
    return a, None


def console(tool, argstr):
    if tool not in {t[0] for t in TOOLS}:
        return {"error": "Unknown tool"}
    try:
        args = shlex.split(argstr or "", posix=not IS_WIN)
    except ValueError as e:
        return {"error": f"Could not parse arguments: {e}"}
    args, msg = guard(tool, args)
    if msg:
        return {"cmd": tool, "rc": 1, "out": "", "err": msg, "seconds": 0}
    cmd = [tool] + args
    t0 = time.time()
    r = run(cmd, CONSOLE_TIMEOUT.get(tool, 45))
    out = r["out"] if len(r["out"]) < 300000 else r["out"][:300000] + "\n...[output truncated]"
    return {"cmd": " ".join(shlex.quote(c) for c in cmd), "rc": r["rc"], "out": out,
            "err": r["err"][-20000:], "seconds": round(time.time() - t0, 1)}


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------
def text_report():
    with STATE_LOCK:
        have_ov, have_h = "overview" in STATE, "health" in STATE
    if not have_ov:
        overview()
    if not have_h:
        health()
    with STATE_LOCK:
        snap = {k: v["data"] for k, v in STATE.items()}
    ov, h = snap["overview"], snap["health"]
    L = []
    w = L.append
    wrap = lambda s, i="  ": textwrap.fill(s, 96, initial_indent=i, subsequent_indent=i)  # noqa: E731
    w("NETPANE NETWORK REPORT")
    w("=" * 96)
    w(f"Host: {ov['hostname']}    Kernel: {ov['kernel']}    Generated: {now()}")
    w(f"Primary interface: {ov['primary']}    Gateway: {(ov.get('gateway') or {}).get('gateway', 'none')}"
      f"    Public IP: {h.get('public_ip') or 'unknown'}")
    w(f"Running as root: {'yes' if ov['root'] else 'no'}")
    w("")
    v = h["verdict"]
    w(f"VERDICT [{v['status'].upper()}]  {v['headline']}")
    w(wrap(v["detail"]))
    if v["ruled_out"]:
        w(wrap("Ruled out: " + ", ".join(v["ruled_out"])))
    for i, s in enumerate(v.get("next", []), 1):
        w(f"  {i}. {s}")
    w("")
    w("LAYER CHECKS")
    w("-" * 96)
    for c in h["checks"]:
        w(f"[{c['status'].upper():4}] {c['layer']:<4} {c['name']:<24}")
        w(wrap(c["detail"], "        "))
        if c["status"] != "pass" and c.get("fix"):
            w(wrap("Fix: " + c["fix"], "        "))
    w("")
    w("INTERFACES")
    w("-" * 96)
    for i in ov["interfaces"]:
        if i["loopback"]:
            continue
        extra = ""
        if i.get("wifi", {}).get("ssid"):
            extra = f" wifi={i['wifi']['ssid']} {i['wifi'].get('signal', '?')}dBm"
        elif i["speed"]:
            extra = f" {i['speed']}Mb/s {i['duplex'] or ''}"
        w(f"  {i['name']:<14} {i['state']:<8} {', '.join(i['ipv4']) or '-':<22} {i['mac']:<18} "
          f"mtu {i['mtu']}{extra}  err {(i['rx_errors'] or 0) + (i['tx_errors'] or 0)} drop {(i['rx_dropped'] or 0) + (i['tx_dropped'] or 0)}")
    w("")
    w("ROUTING AND DNS")
    w("-" * 96)
    for r in ov["routes"]["ipv4"]:
        w(f"  {r.get('dst', ''):<20} via {r.get('gateway', 'direct'):<16} dev {r.get('dev', ''):<10} metric {r.get('metric', '')}")
    d = ov["dns"]
    w(f"  DNS (resolv.conf): {', '.join(d['resolv_conf']) or 'none'}")
    if d["upstream"]:
        w(f"  DNS upstream:      {', '.join(d['upstream'])}")
    if "neighbors" in snap and snap["neighbors"].get("hosts"):
        n = snap["neighbors"]
        w("")
        w(f"NETWORK NEIGHBOURS  ({n['count']} on {n.get('network')} via {n.get('method')})")
        w("-" * 96)
        for x in n["hosts"]:
            w(f"  {x['ip']:<16} {x['mac'] or '-':<18} {(x['name'] or '-')[:28]:<28} {(x['vendor'] or '')[:22]:<22} {x['role'] or x['state']}")
    if "path" in snap and snap["path"].get("hops"):
        p = snap["path"]
        w("")
        w(f"PATH TO {p['target']}  ({p['method']}, destination {'reached' if p.get('reached') else 'NOT reached'})")
        w("-" * 96)
        for x in p["hops"]:
            w(f"  {x['hop']:>2}  {x['host']:<40} loss {x['loss'] if x['loss'] is not None else '?':>5}%  avg {x['avg'] if x['avg'] is not None else '-'} ms")
    try:
        ap = apps()
    except Exception:  # noqa: BLE001
        ap = None
    if ap and ap["apps"]:
        w("")
        w(f"PROGRAMS USING THE NETWORK  ({len(ap['apps'])} processes)")
        w("-" * 96)
        w(f"  {'PID':>7}  {'PROGRAM':<22} {'USER':<10} {'CONNS':>5}  {'DOWN':>10} {'UP':>10}  LISTENING / TALKING TO")
        for x in ap["apps"][:80]:
            to = ", ".join(t["name"] or t["ip"] for t in x["top_peers"][:2])
            extra = ", ".join(x["listening"][:4]) or to
            w(f"  {x['pid']:>7}  {x['app'][:22]:<22} {x['user'][:10]:<10} {x['conns']:>5}  "
              f"{x['rx_rate'] / 1024:>7.1f} KB/s {x['tx_rate'] / 1024:>5.1f} KB/s  {extra[:40]}")
    if "sockets" not in snap:
        try:
            snap["sockets"] = sockets()
        except Exception:  # noqa: BLE001
            pass
    if "sockets" in snap:
        s = snap["sockets"]
        w("")
        w(f"LISTENING PORTS  ({len(s['listening'])})    ESTABLISHED: {len(s['established'])}")
        w("-" * 96)
        for x in s["listening"][:80]:
            w(f"  {x['proto']:<5} {x['local']:<40} {x['process'] or '?'} {('pid ' + x['pid']) if x['pid'] else ''}")
    inv = tool_inventory()
    w("")
    w(f"TOOLS: {inv['installed']} of {len(inv['tools'])} installed")
    if inv["install_cmd"]:
        w("  Missing: " + inv["install_cmd"])
    return "\n".join(L) + "\n"


def json_report():
    text_report()
    with STATE_LOCK:
        return {k: v for k, v in STATE.items()}


# --------------------------------------------------------------------------
# web server
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "NetPane/" + VERSION

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json", extra=None):
        if not isinstance(body, bytes):
            body = (json.dumps(body, default=str) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        try:
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the window closed before the answer arrived

    def host_ok(self):
        return ALLOW_ANY_HOST or self.headers.get("Host", "") in ALLOWED_HOSTS

    def do_GET(self):
        if not self.host_ok():
            return self.send(403, {"error": "Host not allowed"})
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        simple = {"/api/overview": overview, "/api/health": health, "/api/neighbors": discover,
                  "/api/sockets": sockets, "/api/tools": tool_inventory, "/api/wifi": wifi_scan,
                  "/api/traffic": traffic, "/api/apps": apps, "/api/vlan": vlan_scan}
        try:
            if u.path in ("/", "/index.html"):
                return self.send(200, INDEX_HTML, "text/html")
            if u.path in simple:
                return self.send(200, simple[u.path]())
            if u.path == "/api/hello":
                life_hello(q.get("id", ""))
                return self.send(200, {"ok": True, "auto_quit": LIFE["auto_quit"], "version": VERSION})
            if u.path == "/api/path":
                return self.send(200, path(q.get("target", "1.1.1.1")))
            if u.path == "/api/scanhost":
                return self.send(200, scan_host(q.get("ip", "")))
            if u.path == "/api/lookup":
                return self.send(200, lookup(q.get("kind", ""), q.get("target", "")))
            if u.path == "/api/lldp":
                return self.send(200, lldp_listen(int(q.get("t", "65") or 65)))
            stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
            if u.path == "/api/report.txt":
                return self.send(200, text_report(), "text/plain",
                                 {"Content-Disposition": f'attachment; filename="netpane-{socket.gethostname()}-{stamp}.txt"'})
            if u.path == "/api/report.json":
                return self.send(200, json.dumps(json_report(), indent=2, default=str), "application/json",
                                 {"Content-Disposition": f'attachment; filename="netpane-{socket.gethostname()}-{stamp}.json"'})
            self.send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            self.send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self):
        if not self.host_ok():
            return self.send(403, {"error": "Host not allowed"})
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc != self.headers.get("Host"):
            return self.send(403, {"error": "Cross-origin request refused"})
        if self.path == "/api/bye":  # sent by navigator.sendBeacon when the window closes
            n = min(int(self.headers.get("Content-Length", 0)), 200)
            life_bye(self.rfile.read(n).decode(errors="replace").strip())
            return self.send(200, {"ok": True})
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self.send(415, {"error": "JSON required"})
        try:
            n = min(int(self.headers.get("Content-Length", 0)), 100000)
            body = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/api/run":
                return self.send(200, console(str(body.get("tool", "")), str(body.get("args", ""))))
            if self.path == "/api/ssh":
                return self.send(200, ssh_launch(str(body.get("host", "")), str(body.get("user", "")),
                                                 body.get("port", 22)))
            self.send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            self.send(500, {"error": f"{type(e).__name__}: {e}"})


LIFE = {"auto_quit": False, "pages": {}, "lock": threading.Lock()}


def life_hello(pid):
    with LIFE["lock"]:
        LIFE["pages"][pid or "?"] = time.time()


def life_bye(pid):
    with LIFE["lock"]:
        LIFE["pages"].pop(pid or "?", None)
    if LIFE["auto_quit"]:
        threading.Timer(4.0, _maybe_quit).start()


def _watchdog():
    """Safety net for windows that vanish without saying goodbye (crash, kill): quit after 150 s of silence."""
    while True:
        time.sleep(15)
        if not LIFE["auto_quit"]:
            continue
        with LIFE["lock"]:
            seen = list(LIFE["pages"].values())
            LIFE["ever"] = LIFE.get("ever") or bool(seen)
            silent = LIFE["ever"] and all(time.time() - t > 150 for t in seen)
        if silent:
            print("\n  No NetPane window has checked in for 2.5 minutes. Stopped.")
            _cleanup()
            os._exit(0)


def _maybe_quit():
    with LIFE["lock"]:
        if LIFE["pages"]:
            return  # a reload or another window said hello in the meantime
    print("\n  NetPane window closed. Stopped.")
    _cleanup()
    os._exit(0)


def _cleanup():
    p = _NETHOGS.get("proc")
    if p and p.poll() is None:
        p.terminate()


atexit.register(_cleanup)


def _desktop_user():
    """When running as root via sudo or pkexec, return (user, uid) of the person at the desktop."""
    if not IS_ROOT or IS_WIN:
        return None, None
    if os.environ.get("SUDO_USER") and os.environ.get("SUDO_UID"):
        return os.environ["SUDO_USER"], os.environ["SUDO_UID"]
    if os.environ.get("PKEXEC_UID"):
        try:
            import pwd
            return pwd.getpwuid(int(os.environ["PKEXEC_UID"])).pw_name, os.environ["PKEXEC_UID"]
        except Exception:  # noqa: BLE001
            return None, None
    return None, None


def _launch_as_user(cmd):
    """Start a GUI program as the logged-in user, never as root."""
    user, uid = _desktop_user()
    if IS_ROOT and not IS_WIN:
        if not (user and uid and have("sudo")):
            return False
        env = [f"{k}={os.environ[k]}" for k in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY") if k in os.environ]
        env += [f"XDG_RUNTIME_DIR=/run/user/{uid}", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"]
        cmd = ["sudo", "-u", user, "env"] + env + cmd
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                         start_new_session=not IS_WIN)
        return True
    except OSError:
        return False


APP_BROWSERS = ["brave-browser", "brave", "brave-browser-stable", "google-chrome", "google-chrome-stable",
                "chromium", "chromium-browser", "microsoft-edge", "microsoft-edge-stable", "vivaldi", "vivaldi-stable"]


def open_app_window(url):
    """Open NetPane in its own window with no tabs or address bar (Chromium-family app mode)."""
    if IS_WIN:
        return False
    for b in APP_BROWSERS:
        path_ = which(b)
        if path_ and _launch_as_user([path_, f"--app={url}", "--window-size=1380,900", "--class=NetPane"]):
            return b
    return False


def open_browser(url):
    try:
        if IS_ROOT and not IS_WIN:
            if not (have("xdg-open") and _launch_as_user(["xdg-open", url])):
                print(f"  Open {url} in your browser.")
        else:
            webbrowser.open(url)
    except Exception:  # noqa: BLE001
        pass


def open_ui(url, tab=False):
    used = None if tab else open_app_window(url)
    if not used:
        open_browser(url)
    return used


ICON_SVG = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><rect x='1.5' y='1.5' width='21' height='21' "
            "rx='5.5' fill='#15202B'/><rect x='5' y='5' width='6' height='6' rx='1.6' fill='#17914F'/><rect x='13' y='5' "
            "width='6' height='6' rx='1.6' fill='#5C6772'/><rect x='5' y='13' width='6' height='6' rx='1.6' fill='#5C6772'/>"
            "<rect x='13' y='13' width='6' height='6' rx='1.6' fill='#5C6772'/></svg>")


def install_launcher(remove=False):
    home = os.path.expanduser("~")
    if IS_ROOT and os.environ.get("SUDO_USER"):
        print("Run --install without sudo, so it installs for your own user.")
        return
    app_dir = os.path.join(home, ".local", "share", "netpane")
    target = os.path.join(app_dir, "netpane.py")
    icon = os.path.join(home, ".local", "share", "icons", "hicolor", "scalable", "apps", "netpane.svg")
    desk = os.path.join(home, ".local", "share", "applications", "netpane.desktop")
    if remove:
        for f in (desk, icon, target, os.path.join(app_dir, "netpane-admin")):
            try:
                os.remove(f)
                print("  removed", f)
            except OSError:
                pass
        print("NetPane launcher removed.")
        return
    for d in (app_dir, os.path.dirname(icon), os.path.dirname(desk)):
        os.makedirs(d, exist_ok=True)
    shutil.copyfile(os.path.abspath(__file__), target)
    os.chmod(target, 0o755)
    with open(icon, "w") as f:
        f.write(ICON_SVG)
    py = sys.executable or "python3"
    admin = os.path.join(app_dir, "netpane-admin")
    with open(admin, "w") as f:
        f.write("#!/bin/sh\n# Start NetPane as root through the desktop's password prompt (polkit).\n"
                f'exec pkexec env DISPLAY="$DISPLAY" XAUTHORITY="$XAUTHORITY" WAYLAND_DISPLAY="$WAYLAND_DISPLAY" '
                f'XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" {py} {target} "$@"\n')
    os.chmod(admin, 0o755)
    with open(desk, "w") as f:
        f.write(textwrap.dedent(f"""\
            [Desktop Entry]
            Type=Application
            Name=NetPane
            GenericName=Network troubleshooter
            Comment=Find where a network problem is, one layer at a time
            Exec={py} {target}
            Icon=netpane
            Terminal=false
            Categories=Network;Monitor;
            Keywords=network;wifi;dns;ping;traceroute;troubleshoot;
            StartupWMClass=NetPane
            Actions=admin;

            [Desktop Action admin]
            Name=Run with full access
            Exec={admin}
            """))
    os.chmod(desk, 0o755)
    if have("update-desktop-database"):
        run(["update-desktop-database", os.path.dirname(desk)], 15)
    print(f"NetPane is installed for {os.environ.get('USER', 'you')}.")
    print("  Find it in your applications menu. Right-click it and choose 'Run with full access'")
    print("  to run with root (needed for nethogs speeds, arping and every program's name).")
    print(f"  Files: {target}\n         {desk}")


def main():
    global ALLOW_ANY_HOST
    ap = argparse.ArgumentParser(description="NetPane: single pane of glass network troubleshooter")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--bind", default="127.0.0.1",
                    help="address to listen on (default 127.0.0.1; use 0.0.0.0 to open it to your LAN)")
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser automatically")
    ap.add_argument("--report", action="store_true", help="print a text report to the terminal and exit")
    ap.add_argument("--tab", action="store_true", help="open in a normal browser tab instead of an app window")
    ap.add_argument("--keep-running", action="store_true", help="don't stop when the NetPane window is closed")
    ap.add_argument("--install", action="store_true", help="add NetPane to your applications menu (Linux)")
    ap.add_argument("--uninstall", action="store_true", help="remove the applications menu entry (Linux)")
    ap.add_argument("--version", action="version", version=f"NetPane {VERSION}")
    args = ap.parse_args()
    if args.install or args.uninstall:
        return install_launcher(remove=args.uninstall)

    if IS_WIN and psutil is None:
        print("NetPane on Windows needs psutil. Install it with:  pip install psutil")
        sys.exit(1)
    if IS_WIN:
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleTitleW("NetPane")
        except Exception:  # noqa: BLE001
            pass
    if args.report:
        overview(); health(); discover(); path("1.1.1.1"); sockets()
        print(text_report())
        return

    for h in ("127.0.0.1", "localhost", "[::1]", args.bind):
        ALLOWED_HOSTS.add(f"{h}:{args.port}")
    if args.bind in ("0.0.0.0", "::"):
        ALLOW_ANY_HOST = True
    try:
        srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    except OSError:
        url = f"http://127.0.0.1:{args.port}/"
        print(f"\n  Port {args.port} is already in use. NetPane may already be running: {url}")
        print("  Start it with --port 8766 to run a second copy.")
        if not args.no_browser:
            open_ui(url, args.tab)
        return
    threading.Thread(target=sampler, daemon=True).start()
    threading.Thread(target=oui_db, daemon=True).start()
    threading.Thread(target=_watchdog, daemon=True).start()
    url = f"http://{'127.0.0.1' if args.bind in ('0.0.0.0', '::') else args.bind}:{args.port}/"
    print(f"\n  NetPane {VERSION} is running at {url}")
    if not IS_ROOT:
        print(W("  Tip: start with sudo for arping, tcpdump, nethogs and full process names.",
                "  Tip: right-click and choose Run as administrator to see every program name."))
    if args.bind in ("0.0.0.0", "::"):
        print("  Warning: listening on all interfaces. Anyone who can reach this port can run network tools.")
    if not args.no_browser:
        used = open_ui(url, args.tab)
        LIFE["auto_quit"] = not args.keep_running
        if used:
            print(f"  Opened in its own window ({used}).")
    if LIFE["auto_quit"]:
        print(W("  Closing the NetPane window stops it, or press Ctrl+C here.\n",
                "  Closing the NetPane window stops it, or close this console window.\n"))
    else:
        print(W("  Press Ctrl+C to stop.\n", "  Close this window (or press Ctrl+C) to stop NetPane.\n"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")


# --------------------------------------------------------------------------
# the dashboard
# --------------------------------------------------------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetPane</title>
<meta name="color-scheme" content="light dark">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect x='1.5' y='1.5' width='21' height='21' rx='5.5' fill='%2315202B'/%3E%3Crect x='5' y='5' width='6' height='6' rx='1.6' fill='%2317914F'/%3E%3Crect x='13' y='5' width='6' height='6' rx='1.6' fill='%235C6772'/%3E%3Crect x='5' y='13' width='6' height='6' rx='1.6' fill='%235C6772'/%3E%3Crect x='13' y='13' width='6' height='6' rx='1.6' fill='%235C6772'/%3E%3C/svg%3E">
<style>
:root{
 --canvas:#EEF1F4;--surface:#FFFFFF;--sunken:#F5F7F9;--hover:#F1F4F7;--select:#E6EEFD;--chrome:#F7F8FA;
 --ink:#15202B;--ink-2:#4A5866;--ink-3:#77838F;--line:#D9DFE5;--line-2:#E8ECF0;
 --ok:#17914F;--warn:#BD7608;--fail:#D33A2C;--idle:#AEB8C2;
 --ok-soft:#E2F3E9;--warn-soft:#FAEFD9;--fail-soft:#FBE5E2;
 --rx:#2F6FEB;--tx:#0E8C87;--focus:#2F6FEB;
 --shadow:0 1px 2px rgba(21,32,43,.06),0 8px 24px rgba(21,32,43,.07);
 --pop:0 2px 6px rgba(21,32,43,.12),0 12px 32px rgba(21,32,43,.16);
 --sans:-apple-system,BlinkMacSystemFont,"Segoe UI Variable Text","Segoe UI",Ubuntu,Cantarell,"Noto Sans","Helvetica Neue",Arial,sans-serif;
 --mono:ui-monospace,"SF Mono","Cascadia Mono","Ubuntu Mono","DejaVu Sans Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
 --canvas:#0E151C;--surface:#141D26;--sunken:#1A242E;--hover:#1B2630;--select:#1D3150;--chrome:#111921;
 --ink:#E5EBF0;--ink-2:#A8B5C1;--ink-3:#73818E;--line:#283541;--line-2:#1F2B36;
 --ok:#3CBD74;--warn:#E3A43A;--fail:#F0634F;--idle:#4F5D6A;
 --ok-soft:rgba(60,189,116,.13);--warn-soft:rgba(227,164,58,.14);--fail-soft:rgba(240,99,79,.14);
 --rx:#6A9BFF;--tx:#3CC7C0;--focus:#6A9BFF;--shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.25);--pop:0 2px 6px rgba(0,0,0,.4),0 12px 32px rgba(0,0,0,.45)}}
:root[data-theme="dark"]{
 --canvas:#0E151C;--surface:#141D26;--sunken:#1A242E;--hover:#1B2630;--select:#1D3150;--chrome:#111921;
 --ink:#E5EBF0;--ink-2:#A8B5C1;--ink-3:#73818E;--line:#283541;--line-2:#1F2B36;
 --ok:#3CBD74;--warn:#E3A43A;--fail:#F0634F;--idle:#4F5D6A;
 --ok-soft:rgba(60,189,116,.13);--warn-soft:rgba(227,164,58,.14);--fail-soft:rgba(240,99,79,.14);
 --rx:#6A9BFF;--tx:#3CC7C0;--focus:#6A9BFF;--shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.25);--pop:0 2px 6px rgba(0,0,0,.4),0 12px 32px rgba(0,0,0,.45)}
*{box-sizing:border-box}
html,body{margin:0;height:100%;overflow:hidden}
body{background:var(--canvas);color:var(--ink);font:13px/1.45 var(--sans);-webkit-font-smoothing:antialiased;font-variant-numeric:tabular-nums;cursor:default}
.i{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
button,input,select{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--focus);outline-offset:1px;border-radius:5px}
a{color:inherit;-webkit-user-drag:none}
img,svg{-webkit-user-drag:none}
.mono{font-family:var(--mono);font-size:12px}
.muted{color:var(--ink-3)}.soft{color:var(--ink-2)}
.chrome,.side,.bar,.status,th,button,label,.nav,.stage,.ctx,.seg{user-select:none}
::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-thumb{background:var(--line);border-radius:6px;border:3px solid transparent;background-clip:content-box}
::-webkit-scrollbar-thumb:hover{background-color:var(--ink-3)}
::-webkit-scrollbar-track{background:transparent}

/* ---------- shell ---------- */
.app{display:grid;grid-template-columns:212px minmax(0,1fr);height:100vh}
.side{background:var(--chrome);border-right:1px solid var(--line);display:flex;flex-direction:column;padding:12px 8px 8px;min-height:0;overflow:auto}
.brand{display:flex;align-items:center;gap:9px;padding:2px 8px 14px;font-weight:650;font-size:14px;letter-spacing:-.01em}
.brand svg{width:22px;height:22px}
.nav{display:flex;flex-direction:column;gap:1px}
.nav hr{border:0;border-top:1px solid var(--line-2);margin:7px 8px}
.nav button{display:flex;align-items:center;gap:10px;width:100%;height:30px;padding:0 9px;border:0;background:none;border-radius:6px;color:var(--ink-2);text-align:left}
.nav button:hover{background:var(--hover);color:var(--ink)}
.nav button[aria-current="page"]{background:var(--select);color:var(--ink);font-weight:600}
.nav button[aria-current="page"] .i{color:var(--focus)}
.nav .count{margin-left:auto;font-size:11.5px;color:var(--ink-3)}
.nav .led{margin-left:auto}
.side-foot{margin-top:auto;padding:10px 9px 2px;border-top:1px solid var(--line-2);font-size:12px;color:var(--ink-3);line-height:1.5}
.side-foot b{color:var(--ink);font-weight:600}

main{display:flex;flex-direction:column;min-width:0;min-height:0}
.bar{display:flex;align-items:center;gap:8px;height:50px;padding:0 14px 0 20px;border-bottom:1px solid var(--line);background:var(--surface);flex:none}
.bar .ttl{display:flex;flex-direction:column;min-width:0;margin-right:auto}
.bar .ttl b{font-size:14px;font-weight:650;letter-spacing:-.01em}
.bar .ttl span{font-size:12px;color:var(--ink-3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vtools{display:flex;align-items:center;gap:6px}
.sep{width:1px;height:22px;background:var(--line);margin:0 4px}
.content{flex:1;overflow:auto;min-height:0;position:relative}
.view{padding:18px 20px 28px}
.view[hidden]{display:none}
.status{display:flex;align-items:center;gap:0;height:26px;background:var(--chrome);border-top:1px solid var(--line);font-size:11.5px;color:var(--ink-2);flex:none;overflow:hidden;white-space:nowrap}
.status>*{display:flex;align-items:center;gap:6px;padding:0 10px;height:100%;border-right:1px solid var(--line-2)}
.status .grow{flex:1;border-right:0}
.status button{border:0;background:none;cursor:pointer;color:var(--ink-2)}
.status button:hover{background:var(--hover);color:var(--ink)}
.status .led{width:7px;height:7px;box-shadow:none}
.status .mono{font-size:11px}

.btn{display:inline-flex;align-items:center;gap:6px;height:30px;padding:0 11px;border:1px solid var(--line);background:var(--surface);border-radius:6px;text-decoration:none;white-space:nowrap;font-weight:500}
.btn:hover{background:var(--hover)}
.btn:active{transform:translateY(.5px)}
.btn.primary{background:var(--ink);border-color:var(--ink);color:var(--surface)}
.btn.primary:hover{opacity:.9}
.btn[disabled]{opacity:.55;cursor:progress}
.btn.sm{height:26px;padding:0 9px;font-size:12px}
.btn.icon{width:30px;padding:0;justify-content:center}
kbd{font:11px var(--mono);padding:1px 5px;border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;background:var(--sunken);color:var(--ink-2)}
.btn kbd{border:0;background:none;padding:0;opacity:.6;font-size:10.5px}
input.field,select.field{height:30px;padding:0 9px;border:1px solid var(--line);border-radius:6px;background:var(--surface);min-width:0}
input.field::placeholder{color:var(--ink-3)}
.search{position:relative;display:flex;align-items:center}
.search .i{position:absolute;left:8px;color:var(--ink-3);width:14px;height:14px;pointer-events:none}
.search input{padding-left:28px;width:230px}
.switch{display:inline-flex;align-items:center;gap:7px;color:var(--ink-2);font-size:12px}
.switch input{appearance:none;width:28px;height:16px;border-radius:8px;background:var(--line);position:relative;margin:0;transition:background .15s}
.switch input::after{content:"";position:absolute;top:2px;left:2px;width:12px;height:12px;border-radius:50%;background:#fff;transition:transform .15s;box-shadow:0 1px 2px rgba(0,0,0,.2)}
.switch input:checked{background:var(--ok)}.switch input:checked::after{transform:translateX(12px)}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:6px;overflow:hidden;height:30px}
.seg button{border:0;background:var(--surface);padding:0 11px;color:var(--ink-2)}
.seg button+button{border-left:1px solid var(--line)}
.seg button[aria-pressed="true"]{background:var(--select);color:var(--ink);font-weight:600}

.sheet{background:var(--surface);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.sheet+.sheet,.gap{margin-top:14px}
.shead{display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--line-2)}
.shead h2{margin:0;font-size:13px;font-weight:600}
.shead .tools{margin-left:auto;display:flex;gap:6px;align-items:center}
.shead .hint{color:var(--ink-3);font-size:12px}
.sbody{padding:12px 14px}
.split{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:14px;margin-top:14px}
.split>.sheet{margin:0}

/* ---------- status pieces ---------- */
.led{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--idle);flex:none}
.led.ok{background:var(--ok);box-shadow:0 0 0 3px var(--ok-soft)}
.led.warn{background:var(--warn);box-shadow:0 0 0 3px var(--warn-soft)}
.led.fail{background:var(--fail);box-shadow:0 0 0 3px var(--fail-soft)}
.led.busy{background:var(--focus);animation:pulse 1s ease-in-out infinite}
@keyframes pulse{50%{opacity:.35}}
.tag{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:600;padding:1px 7px;border-radius:999px;background:var(--sunken);color:var(--ink-2);white-space:nowrap}
.tag.ok{background:var(--ok-soft);color:var(--ok)}.tag.warn{background:var(--warn-soft);color:var(--warn)}.tag.fail{background:var(--fail-soft);color:var(--fail)}
.chip{display:inline-flex;font-size:11px;padding:0 6px;border-radius:4px;border:1px solid var(--line);color:var(--ink-2);margin-left:6px;white-space:nowrap;font-weight:500;line-height:17px}
.pids{display:flex;flex-wrap:wrap;gap:3px}
.pid{font:11.5px var(--mono);padding:0 5px;border-radius:4px;background:var(--sunken);border:1px solid var(--line-2);color:var(--ink);line-height:18px}

/* ---------- diagnosis ---------- */
.verdict{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:20px 22px 18px;box-shadow:var(--shadow)}
.vstate{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;color:var(--ink-2)}
.verdict h1{font-size:24px;line-height:1.2;letter-spacing:-.018em;font-weight:680;margin:8px 0 6px;max-width:34ch}
.verdict .lede{color:var(--ink-2);max-width:78ch;margin:0}
.verdict.fail .vstate{color:var(--fail)}.verdict.warn .vstate{color:var(--warn)}.verdict.ok .vstate{color:var(--ok)}
.when{color:var(--ink-3);font-size:12px;margin-top:12px}
.chain{list-style:none;margin:20px 0 2px;padding:0;display:grid;grid-template-columns:repeat(7,minmax(0,1fr))}
.stage{position:relative;display:flex;flex-direction:column;align-items:center;text-align:center;gap:1px}
.stage .wire{position:absolute;top:19px;right:50%;width:100%;height:3px;background:var(--line-2);border-radius:2px;z-index:0}
.stage:first-child .wire{display:none}
.stage .wire::after{content:"";position:absolute;inset:0;border-radius:2px;background:var(--idle);transform-origin:left;transform:scaleX(var(--fill,0));transition:transform .35s ease-out;transition-delay:calc(var(--i)*110ms)}
.chain.lit .wire::after{--fill:1}
.stage.ok .wire::after{background:var(--ok)}.stage.warn .wire::after{background:var(--warn)}
.stage.fail .wire::after{background:repeating-linear-gradient(90deg,var(--fail) 0 7px,transparent 7px 12px)}
.node{position:relative;z-index:1;width:40px;height:40px;border-radius:50%;display:grid;place-items:center;border:2px solid var(--idle);background:var(--surface);color:var(--ink-2);transition:border-color .2s,color .2s}
.node .i{width:18px;height:18px}
.stage.ok .node{border-color:var(--ok);color:var(--ok)}
.stage.warn .node{border-color:var(--warn);color:var(--warn)}
.stage.fail .node{border-color:var(--fail);color:var(--fail);background:var(--fail-soft)}
.stage.fault .node{box-shadow:0 0 0 5px var(--fail-soft)}
.stage .sname{font-weight:600;font-size:12.5px;margin-top:6px}
.stage .sstate{font-size:11.5px;color:var(--ink-3)}
.stage.fail .sstate{color:var(--fail)}.stage.warn .sstate{color:var(--warn)}
.facts{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));margin:14px 0 0;background:var(--surface);border:1px solid var(--line);border-radius:10px}
.fact{padding:10px 14px;border-left:1px solid var(--line-2);min-width:0}
.fact:first-child{border-left:0}
.fact dt{font-size:11.5px;color:var(--ink-3)}
.fact dd{margin:2px 0 0;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fact dd.mono{font-size:12.5px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:18px;padding-top:16px;border-top:1px solid var(--line-2)}
.cols h3{font-size:12.5px;margin:0 0 8px;font-weight:600;color:var(--ink-2)}
.ruled{list-style:none;margin:0;padding:0;display:grid;gap:4px}
.ruled li{display:flex;gap:8px;align-items:flex-start;color:var(--ink-2)}
.ruled .i{width:14px;height:14px;color:var(--ok);margin-top:2px}
.steps{margin:0;padding-left:18px;display:grid;gap:4px}
.steps li::marker{color:var(--ink-3);font-weight:600}
.group{padding:4px 0}
.group+.group{border-top:1px solid var(--line-2)}
.ghead{display:flex;align-items:center;gap:8px;padding:8px 14px 2px;font-weight:600;font-size:12px;color:var(--ink-2)}
.ghead .i{width:14px;height:14px}
.check{display:grid;grid-template-columns:16px minmax(130px,180px) minmax(0,1fr);gap:2px 10px;padding:6px 14px;align-items:baseline}
.check .cname{font-weight:550}
.check .cfix{grid-column:3;color:var(--ink-2);font-size:12.5px;display:flex;gap:6px}
.check .cfix b{font-weight:600;color:var(--ink)}
.check .crule{grid-column:3;color:var(--ink-3);font-size:12px}
.group.flash{animation:flash 1.2s ease-out}
@keyframes flash{0%{background:var(--warn-soft)}100%{background:transparent}}

/* ---------- tables ---------- */
.tablewrap{overflow:auto;max-height:calc(100vh - 230px)}
.tablewrap.tall{max-height:none}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-weight:500;font-size:11.5px;color:var(--ink-3);padding:6px 12px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--surface);white-space:nowrap;z-index:1}
th.sort{cursor:pointer}
th.sort:hover{color:var(--ink)}
th .arr{display:inline-block;width:10px;margin-left:3px;opacity:0;font-size:9px}
th.on{color:var(--ink)}th.on .arr{opacity:1}
th.r,td.r{text-align:right}
td{padding:6px 12px;border-bottom:1px solid var(--line-2);vertical-align:middle}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:var(--hover)}
tr.click{cursor:default}
tr.sel td,tr.sel:hover td{background:var(--select)}
tr:focus-visible{outline:none}
tr:focus-visible td{background:var(--select);box-shadow:inset 0 1px 0 var(--focus),inset 0 -1px 0 var(--focus)}
tr:focus-visible td:first-child{box-shadow:inset 2px 0 0 var(--focus),inset 0 1px 0 var(--focus),inset 0 -1px 0 var(--focus)}
.dev{display:flex;align-items:center;gap:10px;min-width:0}
.devicon{width:28px;height:28px;border-radius:7px;background:var(--sunken);display:grid;place-items:center;color:var(--ink-2);flex:none;font-weight:650;font-size:12px}
.devname{font-weight:600}
.devsub{font-size:11.5px;color:var(--ink-3)}
.empty{padding:26px 14px;color:var(--ink-3);text-align:center}
.loading{padding:18px 14px;color:var(--ink-3)}
.loading::before{content:"";display:inline-block;width:11px;height:11px;border:2px solid var(--line);border-top-color:var(--ink-2);border-radius:50%;margin-right:8px;vertical-align:-2px;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.note{display:flex;gap:9px;padding:9px 12px;border-radius:8px;background:var(--warn-soft);font-size:12.5px;margin:10px 14px}
.note .i{color:var(--warn);margin-top:1px}
.note.fail{background:var(--fail-soft)}.note.fail .i{color:var(--fail)}
.note.info{background:var(--sunken)}.note.info .i{color:var(--ink-2)}
.lossbar{display:flex;align-items:center;gap:8px;min-width:110px}
.lossbar span{flex:1;height:5px;border-radius:3px;background:var(--line-2);overflow:hidden}
.lossbar span i{display:block;height:100%;background:var(--ok)}
.lossbar.warn span i{background:var(--warn)}.lossbar.fail span i{background:var(--fail)}
.spd{display:inline-flex;flex-direction:column;align-items:flex-end;gap:2px;min-width:78px}
.spd .v{white-space:nowrap}
.spd .z{color:var(--ink-3)}
.spd .b{display:block;height:3px;border-radius:2px;background:var(--line-2);width:64px;overflow:hidden}
.spd .b i{display:block;height:100%;margin-left:auto}
.spd.rx .b i{background:var(--rx)}.spd.tx .b i{background:var(--tx)}

/* ---------- topology ---------- */
.topo{display:block;width:100%;height:auto;max-height:420px}
.topo .bus{stroke:var(--line);stroke-width:2}
.topo .n{fill:var(--surface);stroke-width:2}
.topo .ico{color:var(--ink-2)}
.topo text{fill:var(--ink);font:600 12px var(--sans)}
.topo text.s{fill:var(--ink-3);font:400 11px var(--mono)}
.topo text.m{fill:var(--ink-3);font:400 13px var(--sans)}
.topo g[data-host]:hover .n{fill:var(--hover)}

/* ---------- traffic ---------- */
.meters{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-top:1px solid var(--line-2)}
.meter{padding:10px 14px;border-left:1px solid var(--line-2)}
.meter:first-child{border-left:0}
.meter dt{font-size:11.5px;color:var(--ink-3);display:flex;align-items:center;gap:7px}
.meter dd{margin:2px 0 0;font-size:19px;font-weight:650;letter-spacing:-.01em}
.sw{width:10px;height:3px;border-radius:2px;display:inline-block}
canvas{display:block;width:100%}

/* ---------- tools ---------- */
.crow{display:flex;gap:6px;flex-wrap:wrap}
.crow input{flex:1;min-width:220px;font-family:var(--mono);font-size:12.5px}
.sshpanel{margin-top:10px;padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--sunken);display:flex;flex-direction:column;gap:10px}
.sshgrid{display:grid;grid-template-columns:1fr 90px;gap:8px}
.sshgrid label{display:flex;flex-direction:column;gap:4px;font-size:11.5px;color:var(--ink-2)}
.sshgrid input{font-family:var(--mono);font-size:12.5px}
.sshcmdrow{background:#0D1319;color:#D7E0E8;border-radius:6px;padding:9px 11px;overflow:auto}
.sshcmdrow code{color:#D7E0E8;white-space:pre-wrap;word-break:break-all;font-size:12.5px}
#sshmsg:empty{display:none}
.presets{display:flex;flex-wrap:wrap;gap:5px;margin-top:10px}
.presets button{border:1px solid var(--line);background:var(--sunken);border-radius:5px;padding:3px 8px;font:11.5px var(--mono);color:var(--ink-2)}
.presets button:hover{color:var(--ink);border-color:var(--ink-3)}
.term{background:#0D1319;color:#D7E0E8;border-radius:8px;padding:12px 14px;white-space:pre-wrap;word-break:break-word;min-height:240px;max-height:58vh;overflow:auto;margin:12px 0 0;font:12px/1.55 var(--mono);user-select:text}
.toolgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}
.tool{display:flex;gap:9px;align-items:flex-start;padding:7px 14px}
.tool .i{width:14px;height:14px;margin-top:2px}
.tool.on .i{color:var(--ok)}.tool.off{color:var(--ink-3)}.tool.off .i{color:var(--ink-3)}
.tool b{font-family:var(--mono);font-weight:600;font-size:12.5px}
.tool div div{font-size:12px;color:var(--ink-3)}
pre.plain{margin:0;font:11.5px/1.5 var(--mono);white-space:pre-wrap;color:var(--ink-2);user-select:text}
.copy{display:flex;gap:8px;align-items:center;background:var(--sunken);border:1px solid var(--line);border-radius:6px;padding:6px 8px;margin-top:6px}
.copy code{flex:1;font:12px var(--mono);overflow-x:auto;white-space:nowrap;user-select:text}

/* ---------- overlays ---------- */
.scrim{position:fixed;inset:0;background:rgba(10,16,22,.32);z-index:40;display:flex;justify-content:flex-end}
.scrim[hidden]{display:none}
.drawer{width:min(600px,100%);height:100%;background:var(--surface);border-left:1px solid var(--line);overflow:auto;padding:18px 20px;animation:slide .18s ease-out;box-shadow:var(--pop)}
@keyframes slide{from{transform:translateX(20px);opacity:.5}}
.dtop h2{margin:0;font-size:17px;letter-spacing:-.01em}
.dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:14px 0;font-size:12.5px}
.dl dt{color:var(--ink-3)}.dl dd{margin:0;min-width:0;overflow-wrap:anywhere;user-select:text}
.drawer .term{min-height:160px}
.drawer .sheet{margin-top:12px}
.dtop{display:flex;align-items:flex-start;gap:12px}
.dtop .devicon{width:40px;height:40px;border-radius:10px;font-size:16px}
.dtop .devicon .i{width:20px;height:20px}
.dtop .x{margin-left:auto}
.ctx{position:fixed;z-index:60;min-width:200px;background:var(--surface);border:1px solid var(--line);border-radius:8px;box-shadow:var(--pop);padding:4px;font-size:12.5px}
.ctx[hidden]{display:none}
.ctx button{display:flex;align-items:center;gap:9px;width:100%;border:0;background:none;padding:6px 9px;border-radius:5px;text-align:left}
.ctx button:hover,.ctx button:focus-visible{background:var(--select);outline:none}
.ctx hr{border:0;border-top:1px solid var(--line-2);margin:4px 2px}
.toasts{position:fixed;right:16px;bottom:38px;z-index:70;display:flex;flex-direction:column;gap:8px;align-items:flex-end;pointer-events:none}
.toast{display:flex;gap:9px;align-items:center;background:var(--ink);color:var(--surface);padding:9px 13px;border-radius:8px;box-shadow:var(--pop);font-size:12.5px;max-width:420px;animation:tin .18s ease-out}
.toast .led{box-shadow:none}
@keyframes tin{from{transform:translateY(8px);opacity:0}}
.keys{position:fixed;inset:0;z-index:80;background:rgba(10,16,22,.42);display:grid;place-items:center}
.keys[hidden]{display:none}
.keys .box{background:var(--surface);border:1px solid var(--line);border-radius:12px;box-shadow:var(--pop);padding:18px 22px;width:min(460px,92vw)}
.keys h2{margin:0 0 10px;font-size:15px}
.keys dl{display:grid;grid-template-columns:auto 1fr;gap:7px 18px;margin:0}
.keys dt{text-align:right}

@media (max-width:1100px){.facts{grid-template-columns:repeat(3,minmax(0,1fr))}.fact:nth-child(4){border-left:0}.fact:nth-child(n+4){border-top:1px solid var(--line-2)}.split{grid-template-columns:1fr}}
@media (max-width:860px){
 html,body{overflow:auto}
 .app{grid-template-columns:1fr;height:auto}
 .side{flex-direction:row;align-items:center;padding:6px 8px;border-right:0;border-bottom:1px solid var(--line);overflow-x:auto;gap:2px;position:sticky;top:0;z-index:20}
 .brand{padding:0 8px 0 4px}.brand span{display:none}
 .nav{flex-direction:row}.nav hr{display:none}.nav button{width:auto;white-space:nowrap}.nav .count,.nav .led{display:none}
 .side-foot{display:none}
 .bar{height:auto;padding:10px 12px;flex-wrap:wrap}
 .vtools{flex-wrap:wrap}.search input{width:100%}
 .content{overflow:visible}
 .view{padding:14px 12px 28px}
 .status{display:none}
 .verdict{padding:16px}.verdict h1{font-size:21px}
 .chain{grid-template-columns:1fr;gap:0}
 .stage{flex-direction:row;text-align:left;gap:10px;padding:5px 0;flex-wrap:wrap}
 .stage .wire{display:none}.stage .sname{margin:0}
 .facts{grid-template-columns:repeat(2,minmax(0,1fr))}.fact{border-left:0!important;border-top:1px solid var(--line-2)}.fact:nth-child(-n+2){border-top:0}
 .cols{grid-template-columns:1fr}
 .check{grid-template-columns:16px minmax(0,1fr)}.check>span:nth-child(n+3){grid-column:2}
 .meters{grid-template-columns:1fr}.meter{border-left:0;border-top:1px solid var(--line-2)}
 .tablewrap{max-height:none}
 .shead .hint{display:none}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style></head><body>

<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<symbol id="i-diag" viewBox="0 0 24 24"><path d="M3 12h4l2.5-6 5 12 2.5-6h4"/></symbol>
<symbol id="i-computer" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></symbol>
<symbol id="i-devices" viewBox="0 0 24 24"><rect x="2.5" y="5" width="13" height="9" rx="1.5"/><path d="M6 18h6M9 14v4"/><rect x="17" y="8" width="4.5" height="10" rx="1.2"/></symbol>
<symbol id="i-path" viewBox="0 0 24 24"><circle cx="6" cy="18" r="2.2"/><circle cx="18" cy="6" r="2.2"/><path d="M8.2 18H14a3 3 0 0 0 0-6h-4a3 3 0 0 1 0-6h5.8"/></symbol>
<symbol id="i-traffic" viewBox="0 0 24 24"><path d="M7 4v16M7 4 4 7M7 4l3 3M17 20V4M17 20l-3-3M17 20l3-3"/></symbol>
<symbol id="i-apps" viewBox="0 0 24 24"><rect x="3.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.6"/><path d="M17 13.5v7M13.5 17h7"/></symbol>
<symbol id="i-port" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M8 15v-3h1.5v-1.5h5V12H16v3z"/></symbol>
<symbol id="i-console" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/></symbol>
<symbol id="i-download" viewBox="0 0 24 24"><path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 20h14"/></symbol>
<symbol id="i-refresh" viewBox="0 0 24 24"><path d="M20 12a8 8 0 1 1-2.4-5.7M20 4v5h-5"/></symbol>
<symbol id="i-moon" viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/></symbol>
<symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6 6 6M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="m5 12.5 4.5 4.5L19 7.5"/></symbol>
<symbol id="i-x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></symbol>
<symbol id="i-alert" viewBox="0 0 24 24"><path d="M12 3.5 2.8 19.5h18.4z"/><path d="M12 10v4M12 17v.01"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.01"/></symbol>
<symbol id="i-router" viewBox="0 0 24 24"><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M10.5 16.5h.01M8.5 9.5a5 5 0 0 1 7 0M6 7a8.5 8.5 0 0 1 12 0"/></symbol>
<symbol id="i-phone" viewBox="0 0 24 24"><rect x="7" y="3" width="10" height="18" rx="2.2"/><path d="M11 18h2"/></symbol>
<symbol id="i-printer" viewBox="0 0 24 24"><path d="M7 9V3.5h10V9"/><rect x="3.5" y="9" width="17" height="7.5" rx="1.5"/><path d="M7 14h10v6.5H7z"/></symbol>
<symbol id="i-server" viewBox="0 0 24 24"><rect x="4" y="3.5" width="16" height="7.5" rx="1.5"/><rect x="4" y="13" width="16" height="7.5" rx="1.5"/><path d="M8 7.25h.01M8 16.75h.01"/></symbol>
<symbol id="i-camera" viewBox="0 0 24 24"><rect x="3" y="7" width="12" height="10" rx="2"/><path d="m15 10.5 6-3v9l-6-3"/></symbol>
<symbol id="i-unknown" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.6 9.4a2.5 2.5 0 1 1 3.4 2.4c-.6.3-1 .8-1 1.5v.4M12 16.8v.01"/></symbol>
<symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.6 2.6 3.8 5.6 3.8 9s-1.2 6.4-3.8 9c-2.6-2.6-3.8-5.6-3.8-9S9.4 5.6 12 3z"/></symbol>
<symbol id="i-dns" viewBox="0 0 24 24"><path d="M4 6.5h10M4 12h16M4 17.5h7"/><circle cx="18" cy="6.5" r="2"/><circle cx="15" cy="17.5" r="2"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9.5" rx="2"/><path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/></symbol>
<symbol id="i-link" viewBox="0 0 24 24"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></symbol>
<symbol id="i-address" viewBox="0 0 24 24"><rect x="3" y="5.5" width="18" height="13" rx="2"/><circle cx="8.5" cy="11" r="2"/><path d="M5.8 15.5c.5-1.3 1.5-2 2.7-2s2.2.7 2.7 2M14 10h4M14 13.5h3"/></symbol>
<symbol id="i-wifi" viewBox="0 0 24 24"><path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.5a9.5 9.5 0 0 1 13 0M8.8 15.8a5 5 0 0 1 6.4 0M12 19.5v.01"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/></symbol>
<symbol id="i-play" viewBox="0 0 24 24"><path d="M8 5.5v13l10-6.5z"/></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5.5A1.5 1.5 0 0 0 14.5 4h-9A1.5 1.5 0 0 0 4 5.5v9A1.5 1.5 0 0 0 5.5 16H8"/></symbol>
<symbol id="i-open" viewBox="0 0 24 24"><path d="M14 4h6v6M20 4l-8 8M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10"/></symbol>
<symbol id="i-keys" viewBox="0 0 24 24"><rect x="2.5" y="6" width="19" height="12" rx="2"/><path d="M6 10h.01M9.5 10h.01M13 10h.01M16.5 10h.01M7 14h10"/></symbol>
</defs></svg>

<div class="app">
 <aside class="side">
  <div class="brand">
   <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="1.5" y="1.5" width="21" height="21" rx="5.5" fill="var(--ink)"/><rect x="5" y="5" width="6" height="6" rx="1.6" fill="var(--ok)"/><rect x="13" y="5" width="6" height="6" rx="1.6" fill="var(--ink-3)"/><rect x="5" y="13" width="6" height="6" rx="1.6" fill="var(--ink-3)"/><rect x="13" y="13" width="6" height="6" rx="1.6" fill="var(--ink-3)"/></svg>
   <span>NetPane</span>
  </div>
  <nav class="nav" aria-label="Sections">
   <button data-go="diagnosis" title="Diagnosis (Ctrl+1)"><svg class="i"><use href="#i-diag"/></svg>Diagnosis<span class="led" id="navled"></span></button>
   <button data-go="devices" title="Devices (Ctrl+2)"><svg class="i"><use href="#i-devices"/></svg>Devices<span class="count" id="navdev"></span></button>
   <button data-go="path" title="Path (Ctrl+3)"><svg class="i"><use href="#i-path"/></svg>Path</button>
   <hr>
   <button data-go="apps" title="Apps (Ctrl+4)"><svg class="i"><use href="#i-apps"/></svg>Apps<span class="count" id="navapps"></span></button>
   <button data-go="traffic" title="Traffic (Ctrl+5)"><svg class="i"><use href="#i-traffic"/></svg>Traffic</button>
   <button data-go="interfaces" title="Interfaces (Ctrl+6)"><svg class="i"><use href="#i-port"/></svg>Interfaces</button>
   <hr>
   <button data-go="tools" title="Tools (Ctrl+7)"><svg class="i"><use href="#i-console"/></svg>Tools</button>
   <button data-go="lookups" title="Lookups (Ctrl+8)"><svg class="i"><use href="#i-search"/></svg>Lookups</button>
  </nav>
  <div class="side-foot" id="hostinfo">Connecting…</div>
 </aside>

 <main>
  <div class="bar">
   <div class="ttl"><b id="bartitle">Diagnosis</b><span id="barsub"></span></div>
   <div class="vtools" id="bartools"></div>
   <div class="sep" id="barsep"></div>
   <a class="btn icon" href="/api/report.txt" id="savebtn" title="Save report (Ctrl+S)"><svg class="i"><use href="#i-download"/></svg></a>
   <button class="btn primary" id="runall" title="Run checks again (Ctrl+R)"><svg class="i"><use href="#i-refresh"/></svg><span>Run checks</span></button>
  </div>

  <div class="content" id="content">

  <!-- DIAGNOSIS -->
  <section class="view" id="v-diagnosis" data-sub="Every layer from this computer out to the web, checked in order.">
   <div class="vtools" data-tools></div>
   <div class="verdict" id="verdict"></div>
   <dl class="facts" id="facts"></dl>
   <div class="sheet gap">
    <div class="shead"><h2>Every check</h2><span class="hint">In the order traffic travels. The first failure is the fault; everything that passed before it is ruled out.</span></div>
    <div id="checks"><div class="loading">Running checks</div></div>
   </div>
  </section>

  <!-- DEVICES -->
  <section class="view" id="v-devices" hidden data-sub="Everything that answered on your local network.">
   <div class="vtools" data-tools>
    <div class="search"><svg class="i"><use href="#i-search"/></svg><input class="field" id="nfilter" placeholder="Filter devices" data-filter></div>
    <button class="btn" id="rescan" title="Scan the subnet again"><svg class="i"><use href="#i-refresh"/></svg>Scan</button>
   </div>
   <div class="sheet"><div class="sbody" id="topo"></div></div>
   <div class="sheet"><div id="neigh"><div class="loading">Scanning the subnet and looking up names</div></div></div>
  </section>

  <!-- PATH -->
  <section class="view" id="v-path" hidden data-sub="Every router between you and a destination, and where delay or loss starts.">
   <form class="vtools" data-tools id="pathf"><input class="field" id="ptarget" value="1.1.1.1" aria-label="Destination" style="width:200px" data-filter><button class="btn">Trace</button></form>
   <div class="sheet"><div id="path"><div class="loading">Tracing</div></div></div>
  </section>

  <!-- APPS -->
  <section class="view" id="v-apps" hidden data-sub="Every program on this computer that has a network connection open.">
   <div class="vtools" data-tools>
    <div class="seg" role="group" aria-label="Group by"><button data-group="app" aria-pressed="true" title="One row per program">By app</button><button data-group="pid" aria-pressed="false" title="One row per process ID">By PID</button></div>
    <div class="search"><svg class="i"><use href="#i-search"/></svg><input class="field" id="afilter" placeholder="Filter by name, PID or address" data-filter></div>
    <label class="switch" title="Refresh every 2 seconds"><input type="checkbox" id="alive" checked> Live</label>
   </div>
   <dl class="facts" id="afacts" style="margin-top:0"></dl>
   <div id="anote"></div>
   <div class="sheet gap"><div id="apps"><div class="loading">Reading every network socket on this computer</div></div></div>
   <div class="sheet"><div class="shead"><h2>Listening ports</h2><span class="hint">Programs waiting for incoming connections. "Network" means other machines can reach it.</span></div><div id="listen"></div></div>
  </section>

  <!-- TRAFFIC -->
  <section class="view" id="v-traffic" hidden data-sub="Live throughput per interface, sampled every second.">
   <div class="vtools" data-tools><select class="field" id="tiface" aria-label="Interface"></select></div>
   <div class="sheet"><div class="sbody"><canvas id="tchart" height="300"></canvas></div><dl class="meters" id="tnow"></dl></div>
   <div class="sheet"><div class="shead"><h2>Busiest apps right now</h2><button class="btn sm" data-go="apps" style="margin-left:auto">Open Apps</button></div><div id="ttop"></div></div>
   <div class="sheet" id="vnstatbox" hidden><div class="shead"><h2>History</h2><span class="hint">from vnstat</span></div><div class="sbody"><pre class="plain" id="vnstat"></pre></div></div>
  </section>

  <!-- INTERFACES -->
  <section class="view" id="v-interfaces" hidden data-sub="Network adapters, addresses, routing and DNS on this computer.">
   <div class="vtools" data-tools></div>
   <div class="sheet"><div id="ifaces"><div class="loading">Reading interfaces</div></div></div>
   <div class="sheet"><div class="shead"><h2>VLAN &amp; segment</h2><button class="btn sm" id="lldpbtn">Listen for a switch (LLDP/CDP)</button></div><div class="sbody" id="vlan"><div class="loading">Checking for a VLAN tag</div></div></div>
   <div class="split">
    <div class="sheet"><div class="shead"><h2>Routing table</h2></div><div id="routes"></div></div>
    <div class="sheet"><div class="shead"><h2>DNS</h2></div><div class="sbody" id="dns"></div></div>
   </div>
   <div class="split">
    <div class="sheet"><div class="shead"><h2>Wi-Fi</h2></div><div id="wifi"></div></div>
    <div class="sheet"><div class="shead"><h2>Hardware</h2></div><div class="sbody" id="hw"></div></div>
   </div>
  </section>

  <!-- TOOLS -->
  <section class="view" id="v-tools" hidden data-sub="Run the underlying tools directly. Safe limits are added so nothing runs forever.">
   <div class="vtools" data-tools></div>
   <div class="sheet"><div class="sbody">
    <div class="crow"><select class="field" id="ctool" aria-label="Tool"></select><input class="field" id="cargs" placeholder="Arguments" aria-label="Arguments" data-filter><button class="btn primary" id="crun"><svg class="i"><use href="#i-play"/></svg>Run</button><button class="btn" id="cclear">Clear</button></div>
    <div class="presets" id="cpresets"></div>
    <pre class="term" id="cout">Choose a tool, then press Run or pick one of the examples.</pre>
   </div></div>
   <div class="sheet"><div class="shead"><h2>Installed tools</h2><span class="hint" id="tcount"></span></div><div id="tools"></div></div>
  </section>

  <!-- LOOKUPS -->
  <section class="view" id="v-lookups" hidden data-sub="Public, read-only intel on a domain, IP or host. Nothing here touches the target beyond a normal query.">
   <div class="vtools" data-tools></div>
   <div class="sheet"><div class="sbody">
    <div class="crow"><input class="field" id="lktarget" placeholder="Domain, IP or host (example.com, 8.8.8.8)" aria-label="Lookup target" autocomplete="off" spellcheck="false"><button class="btn" data-lk="dns">DNS records</button><button class="btn" data-lk="whois">WHOIS</button><button class="btn" data-lk="rdap">RDAP</button><button class="btn" data-lk="tls">TLS cert</button><button class="btn" data-lk="asn">ASN / BGP</button><button class="btn" data-lk="exposure">Exposure</button></div>
    <div class="soft" style="margin-top:6px">DNS, WHOIS and RDAP take a domain or IP. TLS takes a host (optionally host:port). ASN and Exposure take an IP.</div>
   </div></div>
   <div class="sheet" id="lkresult" hidden><div class="shead"><h2 id="lktitle"></h2><span class="hint" id="lksub"></span></div><div class="sbody" id="lkbody"></div></div>
  </section>

  </div>

  <footer class="status" id="status">
   <button id="sb-health" title="Go to Diagnosis"><span class="led busy" id="sb-led"></span><span id="sb-verdict">Checking</span></button>
   <div id="sb-if" class="mono"></div>
   <div id="sb-gw"></div>
   <div id="sb-rate"></div>
   <div id="sb-when"></div>
   <div class="grow"></div>
   <label class="switch" title="Run checks again every minute"><input type="checkbox" id="auto"> Auto-check</label>
   <div id="sb-mode"></div>
   <button id="theme" title="Switch theme"></button>
   <button id="sb-keys" title="Keyboard shortcuts (?)"><svg class="i" style="width:14px;height:14px"><use href="#i-keys"/></svg></button>
  </footer>
 </main>
</div>

<div class="scrim" id="scrim" hidden><aside class="drawer" role="dialog" aria-modal="true" id="drawer"></aside></div>
<div class="ctx" id="ctx" role="menu" hidden></div>
<div class="toasts" id="toasts" aria-live="polite"></div>
<div class="keys" id="keys" hidden><div class="box" role="dialog" aria-label="Keyboard shortcuts">
 <h2>Keyboard shortcuts</h2>
 <dl>
  <dt><kbd>Ctrl</kbd> <kbd>R</kbd></dt><dd>Run all checks again</dd>
  <dt><kbd>Ctrl</kbd> <kbd>1</kbd> to <kbd>7</kbd></dt><dd>Switch page</dd>
  <dt><kbd>/</kbd></dt><dd>Jump to the filter or search box</dd>
  <dt><kbd>↑</kbd> <kbd>↓</kbd></dt><dd>Move through table rows</dd>
  <dt><kbd>Enter</kbd></dt><dd>Open the selected row</dd>
  <dt><kbd>Shift</kbd> <kbd>F10</kbd></dt><dd>Row menu (or right-click)</dd>
  <dt><kbd>Ctrl</kbd> <kbd>S</kbd></dt><dd>Save the text report</dd>
  <dt><kbd>Esc</kbd></dt><dd>Close panels and menus</dd>
 </dl>
</div></div>

<script>
const $=s=>document.querySelector(s);
const $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const ic=(n,c="i")=>`<svg class="${c}"><use href="#i-${n}"/></svg>`;
const S={tif:null,view:"diagnosis",sort:{},rerender:{},group:"app",appsTimer:null};
const WORD={pass:"Passed",warn:"Warning",fail:"Failed",skip:"Not run"};
const CLS={pass:"ok",warn:"warn",fail:"fail",skip:""};
const short=(s,n)=>{s=String(s??"");return s.length>n?s.slice(0,n-1)+"…":s};
function bytes(n){if(n==null)return "";const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1024&&i<4){n/=1024;i++}return n.toFixed(i?1:0)+" "+u[i]}
function rate(Bps){let b=(Bps||0)*8;const u=["bps","Kbps","Mbps","Gbps"];let i=0;while(b>=1000&&i<3){b/=1000;i++}return b.toFixed(i&&b<100?1:0)+" "+u[i]}
function count(a,f){const m={};a.forEach(x=>{const k=f(x);m[k]=(m[k]||0)+1});return Object.entries(m).sort((a,b)=>b[1]-a[1])}
async function api(p,o){const r=await fetch(p,o);let j;try{j=await r.json()}catch(e){throw new Error("NetPane returned an unreadable response ("+r.status+").")}if(!r.ok||(j.error&&!j.hosts&&!j.hops))throw new Error(j.error||("Request failed with "+r.status));return j}
const loading=(id,msg)=>$(id).innerHTML=`<div class="loading">${msg||"Loading"}</div>`;
const fail=(id,e)=>$(id).innerHTML=`<div class="note fail">${ic("alert")}<div>${esc(e.message||e)}</div></div>`;
const KICON={computer:"computer",router:"router",phone:"phone",printer:"printer",server:"server",camera:"camera",unknown:"unknown"};
const ago=t=>{const s=Math.round((Date.now()-t)/1000);return s<10?"just now":s<60?s+" s ago":s<3600?Math.round(s/60)+" min ago":Math.round(s/3600)+" h ago"};

/* ---------- sortable tables ----------
   cols: {k,label,render(row),sort(row)?,r:right-align}; opts: {id,empty,row(row)->attrs,sort:{k,dir},tall} */
function table(cols,rows,o={}){
 if(!rows||!rows.length)return `<div class="empty">${o.empty||"Nothing to show."}</div>`;
 const st=o.id?(S.sort[o.id]||(S.sort[o.id]=o.sort||null)):null;
 let data=rows;
 if(st){const c=cols.find(c=>c.k===st.k);if(c&&c.sort){const f=c.sort;data=[...rows].sort((a,b)=>{const x=f(a),y=f(b);const r=(typeof x==="number"&&typeof y==="number")?x-y:String(x??"").localeCompare(String(y??""),undefined,{numeric:true,sensitivity:"base"});return st.dir==="desc"?-r:r})}}
 const th=cols.map(c=>{const on=st&&st.k===c.k;return `<th class="${c.sort&&o.id?"sort":""}${on?" on":""}${c.r?" r":""}"${c.sort&&o.id?` data-tsort="${o.id}" data-k="${c.k}" aria-sort="${on?(st.dir==="desc"?"descending":"ascending"):"none"}"`:""}>${c.label}${c.sort&&o.id?`<span class="arr">${on&&st.dir==="desc"?"▼":"▲"}</span>`:""}</th>`}).join("");
 return `<div class="tablewrap${o.tall?" tall":""}"><table${o.id?` data-table="${o.id}"`:""}><thead><tr>${th}</tr></thead><tbody>${data.map(r=>`<tr${o.row?o.row(r):""}>${cols.map(c=>`<td${c.r?' class="r"':""}>${c.render(r)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`}
document.addEventListener("click",e=>{const th=e.target.closest("[data-tsort]");if(!th)return;const id=th.dataset.tsort,k=th.dataset.k,cur=S.sort[id];
 S.sort[id]={k,dir:cur&&cur.k===k&&cur.dir==="asc"?"desc":(cur&&cur.k===k?"asc":(th.classList.contains("r")?"desc":"asc"))};(S.rerender[id]||(()=>{}))()});

/* ---------- navigation, toolbar, title ---------- */
const VIEWS=["diagnosis","devices","path","apps","traffic","interfaces","tools","lookups"];
const TITLES={diagnosis:"Diagnosis",devices:"Devices",path:"Path",apps:"Apps",traffic:"Traffic",interfaces:"Interfaces",tools:"Tools",lookups:"Lookups"};
function go(v){if(v==="connections")v="apps";if(!TITLES[v])v="diagnosis";
 const prev=S.view;S.view=v;closeCtx();
 $$(".view").forEach(x=>x.hidden=x.id!=="v-"+v);
 $$(".nav [data-go]").forEach(b=>b.dataset.go===v?b.setAttribute("aria-current","page"):b.removeAttribute("aria-current"));
 const bt=$("#bartools");const old=bt.firstElementChild;if(old&&old.__home)old.__home.appendChild(old);
 const sec=$("#v-"+v),t=sec.__tools||(sec.__tools=sec.querySelector("[data-tools]"));
 if(t){t.__home=t.__home||sec;bt.appendChild(t)}
 $("#barsep").hidden=!(t&&t.children.length);
 $("#bartitle").textContent=TITLES[v];$("#barsub").textContent=sec.dataset.sub||"";
 if(location.hash.slice(1)!==v)history.replaceState(null,"","#"+v);
 $("#content").scrollTop=0;
 if(v==="traffic")drawChart();if(v==="tools")showPresets();if(v==="interfaces")loadVlan();if(v==="lookups")$("#lktarget").focus();
 if(v==="apps"||v==="traffic")startApps();else if(prev==="apps"||prev==="traffic")stopApps()}
function setTheme(t){const r=document.documentElement;if(t)r.dataset.theme=t;else delete r.dataset.theme;
 try{t?localStorage.setItem("np-theme",t):localStorage.removeItem("np-theme")}catch(e){}
 const dark=isDark();$("#theme").innerHTML=ic(dark?"sun":"moon")+(dark?"Light":"Dark");$("#theme").querySelector("svg").style.cssText="width:13px;height:13px";
 drawChart();if(S.ov)drawTopo()}
const isDark=()=>{const t=document.documentElement.dataset.theme;return t?t==="dark":matchMedia("(prefers-color-scheme: dark)").matches};
$("#theme").onclick=()=>setTheme(isDark()?"light":"dark");
try{const t=localStorage.getItem("np-theme");if(t)document.documentElement.dataset.theme=t}catch(e){}
function setTitle(){const v=S.health?.verdict;document.title=v?`NetPane: ${({fail:"Fault found",warn:"Needs attention",pass:"All clear"})[v.status]}`:"NetPane"}

/* ---------- toasts & clipboard ---------- */
function toast(msg,kind){const t=document.createElement("div");t.className="toast";t.innerHTML=(kind?`<span class="led ${kind}"></span>`:"")+esc(msg);$("#toasts").appendChild(t);setTimeout(()=>{t.style.transition="opacity .25s";t.style.opacity="0";setTimeout(()=>t.remove(),260)},3200)}
async function copy(text,label){try{await navigator.clipboard.writeText(text)}catch(e){const a=document.createElement("textarea");a.value=text;document.body.appendChild(a);a.select();document.execCommand("copy");a.remove()}toast(`Copied ${label||text}`)}

/* ---------- status bar ---------- */
function renderStatus(){const o=S.ov,h=S.health;
 if(h){const v=h.verdict,c=CLS[v.status];$("#sb-led").className="led "+c;$("#sb-verdict").textContent=({fail:"Fault found",warn:"Needs attention",pass:"All clear"})[v.status]}
 if(o){const me=(o.interfaces||[]).find(i=>i.name===o.primary);
  $("#sb-if").textContent=o.primary?`${o.primary}  ${me?.ipv4?.[0]||""}`:"No network";
  $("#sb-gw").innerHTML=o.gateway?.gateway?`Gateway <span class="mono">${esc(o.gateway.gateway)}</span>`:"No gateway";
  const win=o.platform==="windows";
  $("#sb-mode").innerHTML=o.root?"Full access":`<span title="${win?"Run as administrator":"Start with sudo"} for every program name and live speeds that include UDP">Limited mode</span>`}
 if(S.checkedAt)$("#sb-when").textContent="Checked "+ago(S.checkedAt)}
setInterval(renderStatus,15000);

/* ---------- overview ---------- */
async function loadOverview(){
 try{const o=await api("/api/overview");S.ov=o;
  const win=o.platform==="windows";
  $("#hostinfo").innerHTML=`<b>${esc(o.hostname)}</b><br>${esc(o.kernel)}<br>NetPane ${esc(o.version)}`;
  if(!S.tif)S.tif=o.primary;renderIfaces();renderRoutes();renderHw();renderFacts();drawTopo();renderStatus();
 }catch(e){fail("#ifaces",e);$("#hostinfo").textContent="Can't reach NetPane. Is it still running?";$("#sb-verdict").textContent="Disconnected";$("#sb-led").className="led fail"}}

function renderIfaces(){const o=S.ov;
 S.rerender.ifaces=renderIfaces;
 $("#ifaces").innerHTML=table([
  {k:"name",label:"Interface",sort:i=>i.name,render:i=>`<div class="dev"><div class="devicon">${ic(i.wireless?"wifi":"port")}</div><div><div class="devname">${esc(i.name)}${i.name===o.primary?'<span class="chip">primary</span>':""}${i.virtual?'<span class="chip">virtual</span>':""}</div><div class="devsub">${esc(i.driver||(i.virtual?"software device":""))}</div></div></div>`},
  {k:"st",label:"Status",sort:i=>i.carrier!=="0"&&i.state!=="DOWN"?0:1,render:i=>{const up=i.carrier!=="0"&&i.state!=="DOWN";return `<span class="tag ${up?(i.state==="UP"?"ok":"warn"):"fail"}">${up?"Connected":"No link"}</span>`}},
  {k:"ip",label:"Address",sort:i=>i.ipv4[0]||"~",render:i=>`<div class="mono">${esc(i.ipv4.join(", ")||"none")}</div>${i.ipv6.length?`<div class="mono muted" style="font-size:11px">${esc(short(i.ipv6[0],30))}</div>`:""}`},
  {k:"mac",label:"Hardware address",sort:i=>i.mac,render:i=>`<div class="mono">${esc(i.mac)}</div><div class="devsub">${esc(i.vendor)}</div>`},
  {k:"spd",label:"Speed",r:1,sort:i=>i.speed||0,render:i=>i.wifi&&i.wifi.ssid?`${esc(i.wifi.ssid)}<div class="devsub">${i.wifi.signal_pct!=null?esc(i.wifi.signal_pct)+"%":esc(i.wifi.signal??"?")+" dBm"}, ${esc(i.wifi.bitrate||"")}</div>`:(i.speed?`${i.speed>=1000?i.speed/1000+" Gb/s":i.speed+" Mb/s"}<div class="devsub">${esc(i.duplex||"")} duplex</div>`:'<span class="muted">n/a</span>')},
  {k:"mtu",label:"MTU",r:1,sort:i=>i.mtu||0,render:i=>esc(i.mtu)},
  {k:"rx",label:"Received",r:1,sort:i=>i.rx_bytes||0,render:i=>bytes(i.rx_bytes)},
  {k:"tx",label:"Sent",r:1,sort:i=>i.tx_bytes||0,render:i=>bytes(i.tx_bytes)},
  {k:"err",label:"Errors",r:1,sort:i=>(i.rx_errors||0)+(i.tx_errors||0),render:i=>{const e=(i.rx_errors||0)+(i.tx_errors||0),d=(i.rx_dropped||0)+(i.tx_dropped||0);return `${e?`<span class="tag fail">${e}</span>`:"0"}${d?`<div class="devsub">${d} dropped</div>`:""}`}}
 ],o.interfaces.filter(i=>!i.loopback),{id:"ifaces",empty:"No network adapters found.",tall:1})}
function renderRoutes(){const o=S.ov;if(!o)return;const d=o.dns;S.rerender.routes=renderRoutes;
 $("#routes").innerHTML=table([{k:"d",label:"Destination",sort:r=>r.dst==="default"?"":r.dst,render:r=>`<span class="mono">${esc(r.dst==="default"?"Everything else (default)":r.dst)}</span>`},{k:"g",label:"Via",sort:r=>r.gateway||"",render:r=>`<span class="mono">${esc(r.gateway||"Direct")}</span>`},{k:"i",label:"Interface",sort:r=>r.dev||"",render:r=>esc(r.dev||"")},{k:"m",label:"Metric",r:1,sort:r=>+r.metric||0,render:r=>esc(r.metric??"")}],o.routes.ipv4,{id:"routes",empty:"No routes. This computer can't reach any network.",tall:1});
 $("#dns").innerHTML=`<dl class="dl" style="margin:0"><dt>Servers</dt><dd class="mono">${esc(d.resolv_conf.join(", ")||"None configured")}${d.stub?' <span class="chip">local cache</span>':""}</dd>
  ${d.upstream.length?`<dt>Forwards to</dt><dd class="mono">${esc(d.upstream.join(", "))}</dd>`:""}
  ${d.search.length?`<dt>Search domains</dt><dd>${esc(d.search.join(", "))}</dd>`:""}
  <dt>Public IP</dt><dd class="mono">${esc(S.health?(S.health.public_ip||"Unknown"):"Checking")}</dd></dl>`}
function renderHw(){const o=S.ov,e=o.extras||{},win=o.platform==="windows";
 let x=`<dl class="dl" style="margin:0 0 10px"><dt>Hostname</dt><dd>${esc(o.fqdn)}</dd><dt>${win?"Windows":"Kernel"}</dt><dd>${esc(o.kernel)}</dd><dt>Running as</dt><dd>${o.root?(win?"Administrator, full access":"root, full access"):esc(o.user||"user")+(win?", limited. Run as administrator for everything.":", limited. Start with sudo for everything.")}</dd></dl>`;
 if(e.pci&&e.pci.length)x+=`<pre class="plain">${esc(e.pci.join("\n"))}</pre>`;
 if(e.nmcli&&e.nmcli.length)x+=`<div style="margin-top:10px">`+table([{k:"a",label:"Device",render:r=>esc(r[0])},{k:"b",label:"Type",render:r=>esc(r[1])},{k:"c",label:"State",render:r=>esc(r[2])},{k:"d",label:"Connection",render:r=>esc(r[3]||"")}],e.nmcli,{tall:1})+`</div>`;
 $("#hw").innerHTML=x;
 if(e.vnstat){$("#vnstatbox").hidden=false;$("#vnstat").textContent=e.vnstat}}

/* ---------- diagnosis ---------- */
const STAGES=[
 {k:"link",name:"Link",icon:"link",checks:["Physical link"]},
 {k:"addr",name:"Address",icon:"address",checks:["IP address","Default route"]},
 {k:"gw",name:"Gateway",icon:"router",checks:["Gateway ARP","Gateway ping"]},
 {k:"net",name:"Internet",icon:"globe",checks:["Internet by IP","TCP egress","MTU / fragmentation"]},
 {k:"dns",name:"DNS",icon:"dns",checks:["DNS servers","Name resolution"]},
 {k:"web",name:"Web",icon:"lock",checks:["HTTPS","Captive portal / proxy"]},
 {k:"q",name:"Quality",icon:"traffic",checks:["Line quality"]}];
function worst(list){const s=list.map(c=>c.status);if(s.includes("fail"))return "fail";if(s.includes("warn"))return "warn";if(s.length&&s.every(x=>x==="skip"))return "skip";return s.length?"pass":"skip"}
function stageState(st,checks){const cs=checks.filter(c=>st.checks.includes(c.name));const w=worst(cs);
 const n={fail:cs.filter(c=>c.status==="fail").length,warn:cs.filter(c=>c.status==="warn").length};
 const label=w==="pass"?"OK":w==="skip"?"Not run":w==="fail"?(n.fail>1?`${n.fail} failed`:"Failed"):(n.warn>1?`${n.warn} warnings`:"Warning");return {w,label,cs}}
function chainHTML(checks){let faultSeen=false;
 return STAGES.map((st,i)=>{const s=checks?stageState(st,checks):{w:"skip",label:"Waiting"};const fault=s.w==="fail"&&!faultSeen;if(fault)faultSeen=true;
  return `<li class="stage ${CLS[s.w]}${fault?" fault":""}" style="--i:${i}"><span class="wire"></span><button class="node" data-stage="${st.k}" title="${esc(st.checks.join(", "))}">${ic(st.icon)}</button><span class="sname">${st.name}</span><span class="sstate">${esc(s.label)}</span></li>`}).join("")}
function renderVerdictWaiting(){
 $("#verdict").className="verdict";
 $("#verdict").innerHTML=`<div class="vstate"><span class="led busy"></span>Checking</div><h1>Looking at your network…</h1><p class="lede">Testing each link from this computer out to the web. This takes about 15 seconds.</p><ol class="chain" id="chain">${chainHTML(null)}</ol>`}
async function loadHealth(){renderVerdictWaiting();loading("#checks","Running checks");$("#navled").className="led busy";$("#sb-led").className="led busy";$("#sb-verdict").textContent="Checking";
 try{S.health=await api("/api/health");S.checkedAt=Date.now();renderHealth();renderRoutes();renderFacts();drawTopo();renderStatus();setTitle();return S.health}catch(e){fail("#checks",e)}}
function renderHealth(){const h=S.health,v=h.verdict,cls=CLS[v.status];
 const state={fail:"Fault found",warn:"Needs attention",pass:"All clear"}[v.status];
 $("#navled").className="led "+cls;
 const steps=(v.next||[]).filter(Boolean);
 $("#verdict").className="verdict "+cls;
 $("#verdict").innerHTML=`<div class="vstate"><span class="led ${cls}"></span>${state}</div>
  <h1>${esc(v.headline)}</h1><p class="lede">${esc(v.detail)}</p>
  <ol class="chain" id="chain">${chainHTML(h.checks)}</ol>
  ${(v.ruled_out.length||steps.length)?`<div class="cols">
   <div><h3>Ruled out</h3>${v.ruled_out.length?`<ul class="ruled">${v.ruled_out.map(r=>`<li>${ic("check")}<span>${esc(r)}</span></li>`).join("")}</ul>`:`<p class="muted" style="margin:0">Nothing yet. The fault is at the very first step.</p>`}</div>
   <div><h3>${steps.length?"What to do next":"If something still fails"}</h3>${steps.length?`<ol class="steps">${steps.map(s=>`<li>${esc(s)}</li>`).join("")}</ol>`:`<p class="soft" style="margin:0">Trace the path to the specific server in Path, or check which program is talking to it in Apps.</p>`}</div></div>`:""}
  <div class="when">Checked at ${esc(h.time.split(" ")[1])} on ${esc(h.interface||"?")}</div>`;
 requestAnimationFrame(()=>requestAnimationFrame(()=>$("#chain")&&$("#chain").classList.add("lit")));
 $("#checks").innerHTML=STAGES.map(st=>{const cs=h.checks.filter(c=>st.checks.includes(c.name));if(!cs.length)return "";
  return `<div class="group" id="g-${st.k}"><div class="ghead">${ic(st.icon)}${st.name}</div>${cs.map(c=>`<div class="check"><span class="led ${CLS[c.status]}" title="${WORD[c.status]}"></span><span class="cname">${esc(c.name)}</span><span class="cdet">${esc(c.detail)}</span>${c.status!=="pass"&&c.fix?`<span class="cfix"><b>Fix</b>${esc(c.fix)}</span>`:""}${c.status==="pass"?`<span class="crule">Rules out ${esc(/^[A-Z][a-z]/.test(c.rules_out)?c.rules_out.charAt(0).toLowerCase()+c.rules_out.slice(1):c.rules_out)}</span>`:""}</div>`).join("")}</div>`}).join("")}
function renderFacts(){const o=S.ov,h=S.health,n=S.neigh;if(!o)return;
 const me=(o.interfaces||[]).find(i=>i.name===o.primary);
 const q=h&&h.checks.find(c=>c.name==="Line quality");const m=q&&q.detail.match(/([\d.]+) ms average/);
 const link=me?(me.wifi&&me.wifi.ssid?`${me.wifi.ssid}${me.wifi.signal_pct!=null?", "+me.wifi.signal_pct+"%":", "+me.wifi.signal+" dBm"}`:(me.speed?(me.speed>=1000?me.speed/1000+" Gb/s":me.speed+" Mb/s")+" wired":me.name)):"None";
 const F=[["This computer",me?.ipv4?.[0]?.split("/")[0]||"No address",1],["Gateway",o.gateway?.gateway||"None",1],["Public IP",h?(h.public_ip||"Unknown"):"Checking",1],
  ["Connection",link,0],["Latency",m?Math.round(+m[1])+" ms":(h?"n/a":"Checking"),0],["Devices nearby",n?(n.error?"n/a":String(n.count)):"Scanning",0]];
 $("#facts").innerHTML=F.map(f=>`<div class="fact"><dt>${f[0]}</dt><dd class="${f[2]?"mono":""}" title="${esc(f[1])}">${esc(f[1])}</dd></div>`).join("")}

/* ---------- devices ---------- */
async function loadNeighbors(){loading("#neigh","Scanning the subnet and looking up names. This can take up to a minute.");$("#navdev").textContent="";$("#rescan").disabled=true;
 try{S.neigh=await api("/api/neighbors");renderNeigh();drawTopo();renderFacts();return S.neigh}catch(e){fail("#neigh",e)}finally{$("#rescan").disabled=false}}
function renderNeigh(){const n=S.neigh;if(!n)return;S.rerender.neigh=renderNeigh;
 if(n.error){$("#neigh").innerHTML=`<div class="note">${ic("alert")}<div>${esc(n.error)}</div></div>`;return}
 $("#v-devices").dataset.sub=`${n.count} ${n.count===1?"device":"devices"} on ${n.network}, found with ${n.method}.`;if(S.view==="devices")$("#barsub").textContent=$("#v-devices").dataset.sub;
 $("#navdev").textContent=n.count;
 const f=$("#nfilter").value.toLowerCase();
 const rows=n.hosts.filter(h=>!f||[h.name,h.ip,h.mac,h.vendor,h.role].join(" ").toLowerCase().includes(f));
 const ipn=ip=>ip.split(".").reduce((a,b)=>a*256+(+b),0);
 $("#neigh").innerHTML=table([
  {k:"name",label:"Device",sort:h=>(h.name||"~").toLowerCase(),render:h=>`<div class="dev"><div class="devicon">${ic(KICON[h.kind]||"unknown")}</div><div><div class="devname">${esc(h.name||"Unnamed device")}${h.role?`<span class="chip">${esc(h.role)}</span>`:""}</div><div class="devsub">${esc(h.name_source?("Name from "+h.name_source):"No name published")}</div></div></div>`},
  {k:"ip",label:"IP address",sort:h=>ipn(h.ip),render:h=>`<span class="mono">${esc(h.ip)}</span>`},
  {k:"mac",label:"Hardware address",sort:h=>h.mac||"~",render:h=>`<span class="mono">${esc(h.mac||"Unknown")}</span>`},
  {k:"v",label:"Maker",sort:h=>h.vendor||"~",render:h=>esc(h.vendor||"Unknown")},
  {k:"st",label:"Status",sort:h=>h.alive?0:1,render:h=>`<span class="tag ${h.alive?"ok":"warn"}">${h.alive?"Online":"Seen recently"}</span>`}],
  rows,{id:"neigh",sort:{k:"ip",dir:"asc"},empty:f?"No devices match that filter.":"No other devices answered.",
  row:h=>` class="click" tabindex="0" data-host="${esc(h.ip)}" data-menu="device" data-ip="${esc(h.ip)}" data-mac="${esc(h.mac||"")}" data-name="${esc(h.name||"")}"`})}
function showHost(ip){const h=(S.neigh?.hosts||[]).find(x=>x.ip===ip)||{ip,name:ip===S.ov?.gateway?.gateway?"Gateway":"",kind:"router"};
 const kind=KICON[h.kind]||"unknown";
 openDrawer(`<div class="dtop"><div class="devicon">${ic(kind)}</div><div><h2>${esc(h.name||"Unnamed device")}</h2><div class="muted mono">${esc(ip)}</div></div><button class="btn icon x" data-close aria-label="Close">${ic("x")}</button></div>
  <dl class="dl"><dt>Hardware address</dt><dd class="mono">${esc(h.mac||"Unknown")}</dd><dt>Maker</dt><dd>${esc(h.vendor||"Unknown")}</dd>
  <dt>Name from</dt><dd>${esc(h.name_source||"Not published")}</dd><dt>Role</dt><dd>${esc(h.role||"Device on this network")}</dd><dt>Neighbour state</dt><dd>${esc(h.state||"")}</dd><dt>Likely type</dt><dd id="dguess">Scan its ports to find out</dd></dl>
  <div class="crow"><button class="btn" data-act="ping">Ping</button><button class="btn primary" data-act="scan">Scan ports</button><button class="btn" data-act="trace">Trace path</button><button class="btn" id="sshbtn">${ic("keys")}SSH login</button><button class="btn" data-copy="${esc(ip)}">${ic("copy")}Copy IP</button></div>
  <div id="sshbox"></div>
  <pre class="term" id="hout">Results appear here.</pre>`);
 $("#drawer").querySelectorAll("[data-act]").forEach(b=>b.onclick=()=>hostAction(ip,b.dataset.act,b));
 const sb=$("#sshbtn");if(sb)sb.onclick=()=>sshForm(ip)}
function sshForm(ip){const box=$("#sshbox");if(!box)return;
 if(box.dataset.open==="1"){box.dataset.open="0";box.innerHTML="";return}
 box.dataset.open="1";
 box.innerHTML=`<div class="sshpanel">
   <div class="sshgrid">
     <label>Username<input id="sshuser" class="field" placeholder="e.g. admin" autocomplete="off" spellcheck="false"></label>
     <label>Port<input id="sshport" class="field" value="22" inputmode="numeric" autocomplete="off"></label>
   </div>
   <div class="sshcmdrow"><code id="sshcmd" class="mono"></code></div>
   <div class="crow"><button class="btn primary" id="sshgo">${ic("play")}Open in terminal</button><button class="btn" id="sshcopy">${ic("copy")}Copy command</button></div>
   <div class="soft">NetPane opens your terminal with this command ready. You type the password there. It is never sent to or stored by NetPane.</div>
   <div id="sshmsg" class="soft"></div>
 </div>`;
 const u=$("#sshuser"),p=$("#sshport"),c=$("#sshcmd");
 const build=()=>{const user=(u.value||"").trim(),port=(p.value||"").trim();
   let cmd="ssh ";if(port&&port!=="22")cmd+="-p "+port+" ";cmd+=(user?user+"@":"")+ip;return cmd};
 const paint=()=>{c.textContent=build()};paint();
 u.oninput=paint;p.oninput=paint;u.focus();
 $("#sshcopy").onclick=()=>copy(build(),"SSH command");
 $("#sshgo").onclick=async b=>{const msg=$("#sshmsg"),user=(u.value||"").trim(),port=(p.value||"").trim()||"22";
   if(!user){msg.innerHTML=`<span class="tag warn">Enter a username first</span>`;u.focus();return}
   msg.textContent="Opening a terminal…";
   try{const r=await api("/api/ssh",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({host:ip,user,port})});
     if(r.ok){msg.innerHTML=`<span class="tag ok">Terminal opened (${esc(r.terminal)})</span> Type the password in that window.`;toast("SSH terminal opened")}
     else if(r.no_terminal){msg.innerHTML=`<span class="tag warn">No terminal found.</span> Copy the command and run it in your own.`}
     else{msg.innerHTML=`<span class="tag fail">${esc(r.error||"Could not open a terminal")}</span>`}}
   catch(e){msg.innerHTML=`<span class="tag fail">${esc(e.message)}</span>`}}}
async function hostAction(ip,act,b){const out=$("#hout");if(out)out.textContent="Running…";if(b)b.disabled=true;
 try{let t;if(act==="scan"){const r=await api("/api/scanhost?ip="+encodeURIComponent(ip));const g=$("#dguess");if(g)g.textContent=r.guess;
    t=`${r.method}\n\n`+(r.ports.length?"PORT    PROTO  SERVICE\n"+r.ports.map(p=>`${String(p.port).padEnd(8)}${p.proto.padEnd(7)}${p.service}`).join("\n"):"No open ports found.")}
  else if(act==="ping")t=await runTool("ping",S.ov?.platform==="windows"?`-n 4 ${ip}`:`-c 4 ${ip}`);
  else{const has=c=>(S.tools||[]).find(x=>x.cmd===c&&x.installed);t=await runTool(has("mtr")?"mtr":has("tracert")?"tracert":"traceroute",has("tracert")?`-d ${ip}`:`-n ${ip}`)}
  if(out)out.textContent=t}catch(e){if(out)out.textContent=e.message}if(b)b.disabled=false}
function openDrawer(html){$("#drawer").innerHTML=html;$("#scrim").hidden=false;const x=$("#drawer [data-close]");if(x)x.focus()}
function closeDrawer(){$("#scrim").hidden=true;S.drawerApp=null}
$("#scrim").onclick=e=>{if(e.target.id==="scrim")closeDrawer()};

/* ---------- topology ---------- */
function drawTopo(){const o=S.ov,h=S.health,n=S.neigh;if(!o)return;
 const st=nm=>(h?.checks||[]).find(c=>c.name===nm)?.status||"skip";
 const w=(...a)=>a.includes("fail")?"fail":a.includes("warn")?"warn":a.every(x=>x==="skip")?"skip":"pass";
 const col=s=>({pass:"var(--ok)",warn:"var(--warn)",fail:"var(--fail)",skip:"var(--idle)"}[s]);
 const sLan=w(st("Physical link"),st("Gateway ARP")),sGw=w(st("Gateway ARP"),st("Gateway ping")),sWan=w(st("Internet by IP"),st("TCP egress"),st("DNS servers"),st("HTTPS"));
 const gw=o.gateway?.gateway,me=(o.interfaces||[]).find(i=>i.name===o.primary);
 const others=(n?.hosts||[]).filter(x=>x.role!=="This host"&&x.role!=="Gateway");
 const per=7,rows=Math.max(1,Math.ceil(others.length/per)),W=1000,busY=150,H=others.length?busY+36+rows*92:busY+80;
 const big=(x,y,icon,label,sub,s,ip)=>`<g${ip?` data-host="${esc(ip)}" data-menu="device" data-ip="${esc(ip)}"`:""}><circle class="n" cx="${x}" cy="${y}" r="28" stroke="${col(s)}"/><svg class="ico" x="${x-12}" y="${y-12}" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><use href="#i-${icon}"/></svg><text x="${x}" y="${y+48}" text-anchor="middle">${esc(label)}</text><text class="s" x="${x}" y="${y+63}" text-anchor="middle">${esc(sub)}</text></g>`;
 const wire=(x1,x2,y,s)=>`<line x1="${x1+30}" y1="${y}" x2="${x2-30}" y2="${y}" stroke="${col(s)}" stroke-width="3" stroke-linecap="round"${s==="fail"?' stroke-dasharray="7 6"':""}/>`;
 let g=`<svg class="topo" viewBox="0 0 ${W} ${H}" role="img" aria-label="Network map">`;
 g+=wire(140,500,52,sLan)+wire(500,860,52,sWan);
 g+=`<line class="bus" x1="60" y1="${busY}" x2="${W-60}" y2="${busY}"/><line class="bus" x1="500" y1="124" x2="500" y2="${busY}"/><line class="bus" x1="140" y1="124" x2="140" y2="${busY}"/>`;
 g+=`<text class="s" x="${W-60}" y="${busY-8}" text-anchor="end">${esc(n?.network||"local network")}</text>`;
 if(!n)g+=`<text class="m" x="${W/2}" y="${busY+50}" text-anchor="middle">Looking for devices…</text>`;
 else if(!others.length)g+=`<text class="m" x="${W/2}" y="${busY+50}" text-anchor="middle">No other devices answered on this network.</text>`;
 const step=(W-120)/per;
 others.forEach((x,i)=>{const cx=60+step/2+(i%per)*step,cy=busY+44+Math.floor(i/per)*92;
  if(i<per)g+=`<line class="bus" x1="${cx}" y1="${busY}" x2="${cx}" y2="${cy-20}"/>`;
  g+=`<g data-host="${esc(x.ip)}" data-menu="device" data-ip="${esc(x.ip)}" data-mac="${esc(x.mac||"")}" data-name="${esc(x.name||"")}"><title>${esc((x.name||"Unnamed")+"  "+x.ip+"  "+(x.vendor||""))}</title><circle class="n" cx="${cx}" cy="${cy}" r="19" stroke="${x.alive?"var(--ok)":"var(--warn)"}"/><svg class="ico" x="${cx-9}" y="${cy-9}" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><use href="#i-${KICON[x.kind]||"unknown"}"/></svg><text x="${cx}" y="${cy+36}" text-anchor="middle" style="font-size:11.5px">${esc(short(x.name||x.vendor||"Unnamed",18))}</text><text class="s" x="${cx}" y="${cy+50}" text-anchor="middle">${esc(x.ip)}</text></g>`});
 g+=big(140,52,"computer","This computer",me?.ipv4?.[0]?.split("/")[0]||"",w(st("Physical link"),st("IP address")),null)+big(500,52,"router","Gateway",gw||"none",gw?sGw:"fail",gw)+big(860,52,"globe","Internet",h?.public_ip||"",sWan,null);
 $("#topo").innerHTML=g+"</svg>"}

/* ---------- path ---------- */
async function loadPath(t){t=t||$("#ptarget").value.trim()||"1.1.1.1";$("#ptarget").value=t;loading("#path",`Tracing the route to ${esc(t)}. This takes up to a minute.`);
 try{S.path=await api("/api/path?target="+encodeURIComponent(t));renderPath();drawTopo();return S.path}catch(e){fail("#path",e)}}
function renderPath(){const p=S.path;if(!p)return;S.rerender.path=renderPath;if(p.error&&!p.hops.length){$("#path").innerHTML=`<div class="note fail">${ic("alert")}<div>${esc(p.error)}</div></div>`;return}
 const hops=p.hops;let bad=-1;const last=hops[hops.length-1];
 if(last&&last.loss>0){for(let i=hops.length-1;i>=0;i--){if(hops[i].loss>0)bad=i;else break}}
 const lb=l=>{const c=l==null?"":l>=100?"fail":l>0?"warn":"";return `<div class="lossbar ${c}"><span><i style="width:${l==null?0:Math.max(l,l>0?4:0)}%"></i></span>${l==null?"?":l+"%"}</div>`};
 const ms=v=>v!=null?v+" ms":"";
 $("#path").innerHTML=`<div class="shead"><h2>${esc(p.target)}${p.dest_ip&&p.dest_ip!==p.target?` <span class="muted mono" style="font-weight:400">${esc(p.dest_ip)}</span>`:""}</h2><div class="tools">${p.reached?'<span class="tag ok">Destination reached</span>':'<span class="tag fail">Destination not reached</span>'}<span class="hint">${esc(p.method)}</span></div></div>`+
 (bad>=0?`<div class="note fail">${ic("alert")}<div>Loss starts at hop ${esc(hops[bad].hop)} (<span class="mono">${esc(hops[bad].host)}</span>) and continues to the end. That router, or the link just before it, is the likely problem.</div></div>`:"")+
 table([{k:"hop",label:"Hop",r:1,sort:h=>h.hop,render:h=>`<span class="muted">${esc(h.hop)}</span>`},{k:"host",label:"Router",sort:h=>h.host,render:h=>`<span class="mono">${esc(h.host==="???"?"No reply":h.host)}</span>${h.name?`<div class="devsub">${esc(short(h.name,52))}</div>`:""}`},
  {k:"loss",label:"Loss",sort:h=>h.loss??101,render:h=>lb(h.loss)},{k:"avg",label:"Average",r:1,sort:h=>h.loss<100?h.avg??1e9:1e9,render:h=>h.loss<100?ms(h.avg):"<span class='muted'>n/a</span>"},{k:"best",label:"Best",r:1,sort:h=>h.best??1e9,render:h=>h.loss<100?ms(h.best):""},{k:"worst",label:"Worst",r:1,sort:h=>h.worst??1e9,render:h=>h.loss<100?ms(h.worst):""}],
  hops,{id:"path",sort:{k:"hop",dir:"asc"},tall:1,row:h=>h.host&&h.host!=="???"?` tabindex="0" data-menu="hop" data-ip="${esc(h.host)}" data-name="${esc(h.name||"")}"`:""})+
 `<div class="note info">${ic("info")}<div>Loss on a single middle hop that doesn't continue to the end is usually that router choosing not to answer pings. It isn't a fault.</div></div>`}

/* ---------- apps ---------- */
function startApps(){if(S.appsTimer)return;const tick=async()=>{if(document.hidden||(S.view!=="apps"&&S.view!=="traffic")){S.appsTimer=setTimeout(tick,2000);return}
  await loadApps();S.appsTimer=setTimeout(tick,$("#alive").checked||S.view==="traffic"?2000:30000)};tick()}
function stopApps(){clearTimeout(S.appsTimer);S.appsTimer=null}
async function loadApps(){try{S.apps=await api("/api/apps");renderApps();renderTopApps()}catch(e){if(!S.apps)fail("#apps",e)}}
const avatar=a=>`<div class="devicon">${esc((a.app||"?").replace(/[^A-Za-z0-9]/g,"").charAt(0).toUpperCase()||"?")}</div>`;
function spd(v,max,dir){const z=!v||v<1;return `<div class="spd ${dir}"><span class="v${z?" z":""}">${z?"0":rate(v)}</span><span class="b"><i style="width:${max>0?Math.min(100,Math.round(100*(v||0)/max)):0}%"></i></span></div>`}
function appGroups(list){const g={};list.forEach(p=>{const k=p.app+"|"+p.user;const x=g[k]||(g[k]={key:k,app:p.app,user:p.user,pids:[],roles:new Set(),conns:0,listening:[],udp:0,rx_rate:0,tx_rate:0,rx_total:0,tx_total:0,exe:p.exe,procs:[],peers:{}});
  x.pids.push(p.pid);if(p.role)x.roles.add(p.role);x.conns+=p.conns;x.listening.push(...p.listening);x.udp+=p.udp;x.rx_rate+=p.rx_rate;x.tx_rate+=p.tx_rate;x.rx_total+=p.rx_total;x.tx_total+=p.tx_total;x.procs.push(p);
  (p.top_peers||[]).forEach(t=>{const y=x.peers[t.ip]||(x.peers[t.ip]={ip:t.ip,name:t.name,count:0});y.count+=t.count;if(t.name)y.name=t.name})});
 return Object.values(g).map(x=>{x.pids.sort((a,b)=>a-b);x.listening=[...new Set(x.listening)];x.top=Object.values(x.peers).sort((a,b)=>b.count-a.count)[0];return x})}
function renderApps(){const d=S.apps;if(!d)return;S.rerender.apps=renderApps;
 const f=$("#afilter").value.trim().toLowerCase();
 const procs=d.apps.filter(p=>!f||[p.app,p.comm,p.pid,p.user,p.cmd,p.role,...p.sockets.map(s=>s.peer+" "+s.peer_name+" "+s.local)].join(" ").toLowerCase().includes(f));
 const totRx=d.apps.reduce((a,p)=>a+p.rx_rate,0),totTx=d.apps.reduce((a,p)=>a+p.tx_rate,0),conns=d.apps.reduce((a,p)=>a+p.conns,0);
 const listening=d.apps.flatMap(p=>p.sockets.filter(s=>s.state==="LISTEN"||(s.proto==="udp"&&s.state==="UNCONN")).map(s=>({...s,app:p.app,pid:p.pid,user:p.user})));
 const groups=appGroups(d.apps);
 $("#navapps").textContent=groups.length;
 $("#afacts").innerHTML=[["Programs online",groups.length],["Processes",d.apps.length],["Open connections",conns],["Download",rate(totRx)],["Upload",rate(totTx)],["Listening ports",listening.length]]
  .map(x=>`<div class="fact"><dt>${x[0]}</dt><dd>${esc(x[1])}</dd></div>`).join("");
 $("#anote").innerHTML=[d.hidden&&`<div class="note info" style="margin:12px 0 0">${ic("info")}<div>${esc(d.hidden)}</div></div>`,d.note&&`<div class="note info" style="margin:8px 0 0">${ic("info")}<div>${esc(d.note)}</div></div>`].filter(Boolean).join("");
 const pidChips=pids=>`<div class="pids">${pids.slice(0,6).map(p=>`<span class="pid">${p}</span>`).join("")}${pids.length>6?`<span class="pid">+${pids.length-6}</span>`:""}</div>`;
 const peer=t=>t?`${esc(short(t.name||t.ip,34))}${t.name?`<div class="devsub mono">${esc(t.ip)}</div>`:""}`:'<span class="muted">None</span>';
 if(S.group==="app"){
  const rows=groups.filter(g=>!f||g.procs.some(p=>procs.includes(p)));
  const mx=Math.max(1,...rows.map(r=>Math.max(r.rx_rate,r.tx_rate)));
  $("#apps").innerHTML=table([
   {k:"app",label:"App",sort:g=>g.app.toLowerCase(),render:g=>`<div class="dev">${avatar(g)}<div><div class="devname">${esc(g.app)}</div><div class="devsub">${esc(g.roles.size?[...g.roles].join(", "):(g.exe||g.procs[0].comm||""))}</div></div></div>`},
   {k:"pid",label:"PIDs",sort:g=>g.pids[0],render:g=>pidChips(g.pids)},
   {k:"user",label:"User",sort:g=>g.user,render:g=>esc(g.user)},
   {k:"conns",label:"Connections",r:1,sort:g=>g.conns,render:g=>g.conns||'<span class="muted">0</span>'},
   {k:"lis",label:"Listening",sort:g=>g.listening.length,render:g=>g.listening.length?`<span class="mono">${esc(short(g.listening.join(", "),26))}</span>`:'<span class="muted">No</span>'},
   {k:"rx",label:"Download",r:1,sort:g=>g.rx_rate,render:g=>spd(g.rx_rate,mx,"rx")},
   {k:"tx",label:"Upload",r:1,sort:g=>g.tx_rate,render:g=>spd(g.tx_rate,mx,"tx")},
   {k:"peer",label:"Talking to",sort:g=>g.top?(g.top.name||g.top.ip):"~",render:g=>peer(g.top)}],
   rows,{id:"apps",sort:{k:"rx",dir:"desc"},empty:f?"No programs match that filter.":"No programs have a network connection open.",
   row:g=>` class="click${S.drawerApp===g.key?" sel":""}" tabindex="0" data-app="${esc(g.key)}" data-menu="app" data-pids="${g.pids.join(" ")}" data-name="${esc(g.app)}"`})}
 else{
  const mx=Math.max(1,...procs.map(r=>Math.max(r.rx_rate,r.tx_rate)));
  $("#apps").innerHTML=table([
   {k:"pid",label:"PID",r:1,sort:p=>p.pid,render:p=>`<span class="pid">${p.pid}</span>`},
   {k:"app",label:"Program",sort:p=>p.app.toLowerCase(),render:p=>`<div class="dev">${avatar(p)}<div><div class="devname">${esc(p.app)}</div><div class="devsub">${esc(p.role||p.comm)}</div></div></div>`},
   {k:"user",label:"User",sort:p=>p.user,render:p=>esc(p.user)},
   {k:"conns",label:"Connections",r:1,sort:p=>p.conns,render:p=>p.conns||'<span class="muted">0</span>'},
   {k:"lis",label:"Listening",sort:p=>p.listening.length,render:p=>p.listening.length?`<span class="mono">${esc(short(p.listening.join(", "),22))}</span>`:'<span class="muted">No</span>'},
   {k:"rx",label:"Download",r:1,sort:p=>p.rx_rate,render:p=>spd(p.rx_rate,mx,"rx")},
   {k:"tx",label:"Upload",r:1,sort:p=>p.tx_rate,render:p=>spd(p.tx_rate,mx,"tx")},
   {k:"cmd",label:"Command",sort:p=>p.cmd,render:p=>`<span class="mono muted" title="${esc(p.cmd)}">${esc(short(p.cmd||p.exe,48))}</span>`}],
   procs,{id:"procs",sort:{k:"rx",dir:"desc"},empty:f?"No processes match that filter.":"No processes have a network connection open.",
   row:p=>` class="click${S.drawerApp==="pid:"+p.pid?" sel":""}" tabindex="0" data-app="pid:${p.pid}" data-menu="app" data-pids="${p.pid}" data-name="${esc(p.app)}"`})}
 S.rerender.procs=renderApps;
 $("#listen").innerHTML=table([
  {k:"port",label:"Port",r:1,sort:r=>+r.local.split(":").pop()||0,render:r=>`<span class="mono">${esc(r.local.split(":").pop())}</span>`},
  {k:"proto",label:"Protocol",sort:r=>r.proto,render:r=>esc(r.proto.toUpperCase())},
  {k:"bind",label:"Bound to",sort:r=>r.local,render:r=>`<span class="mono">${esc(r.local.replace(/:[^:]*$/,""))}</span>`},
  {k:"exp",label:"Reachable from",sort:r=>/^(127\.|\[::1\]|::1|localhost)/.test(r.local)?1:0,render:r=>/^(127\.|\[::1\]|::1|localhost)/.test(r.local)?'<span class="muted">This computer only</span>':'<span class="tag warn">Network</span>'},
  {k:"app",label:"Program",sort:r=>r.app.toLowerCase(),render:r=>esc(r.app)},
  {k:"pid",label:"PID",r:1,sort:r=>r.pid,render:r=>`<span class="pid">${r.pid}</span>`}],
  listening,{id:"listen",sort:{k:"port",dir:"asc"},tall:1,empty:"Nothing is listening for incoming connections.",
  row:r=>` tabindex="0" data-menu="app" data-pids="${r.pid}" data-name="${esc(r.app)}" data-port="${esc(r.local.split(":").pop())}"`});
 if(S.drawerApp&&!$("#scrim").hidden)renderAppDrawer(true)}
function renderTopApps(){const d=S.apps;if(!d||!$("#ttop"))return;const g=appGroups(d.apps).sort((a,b)=>(b.rx_rate+b.tx_rate)-(a.rx_rate+a.tx_rate)).slice(0,5);
 const mx=Math.max(1,...g.map(r=>Math.max(r.rx_rate,r.tx_rate)));
 $("#ttop").innerHTML=table([{k:"a",label:"App",render:x=>`<div class="dev">${avatar(x)}<div class="devname">${esc(x.app)}</div></div>`},{k:"p",label:"PIDs",render:x=>`<div class="pids">${x.pids.slice(0,6).map(p=>`<span class="pid">${p}</span>`).join("")}</div>`},{k:"rx",label:"Download",r:1,render:x=>spd(x.rx_rate,mx,"rx")},{k:"tx",label:"Upload",r:1,render:x=>spd(x.tx_rate,mx,"tx")}],g,{tall:1,empty:"No programs are using the network.",row:x=>` class="click" tabindex="0" data-app="${esc(x.key)}" data-menu="app" data-pids="${x.pids.join(" ")}" data-name="${esc(x.app)}"`})}
function showApp(key){S.drawerApp=key;renderAppDrawer(false);$$("[data-app]").forEach(r=>r.classList.toggle("sel",r.dataset.app===key))}
function renderAppDrawer(live){const d=S.apps;if(!d)return;const key=S.drawerApp;let procs;
 if(key.startsWith("pid:"))procs=d.apps.filter(p=>p.pid===+key.slice(4));else procs=appGroups(d.apps).find(g=>g.key===key)?.procs||[];
 const dr=$("#drawer"),top=dr.scrollTop;
 if(!procs.length){if(live){const t=$("#adr-state");if(t)t.innerHTML='<span class="tag warn">Closed its connections</span>'}return}
 const a=procs[0],pids=procs.map(p=>p.pid).sort((x,y)=>x-y),rx=procs.reduce((s,p)=>s+p.rx_rate,0),tx=procs.reduce((s,p)=>s+p.tx_rate,0);
 const socks=procs.flatMap(p=>p.sockets.map(s=>({...s,pid:p.pid})));
 const html=`<div class="dtop">${avatar(a)}<div><h2>${esc(a.app)}</h2><div class="muted" id="adr-state">${pids.length} ${pids.length===1?"process":"processes"}, ${esc(a.user)}</div></div><button class="btn icon x" data-close aria-label="Close">${ic("x")}</button></div>
  <dl class="dl"><dt>PIDs</dt><dd><div class="pids">${pids.map(p=>`<span class="pid">${p}</span>`).join("")}</div></dd>
  <dt>Download now</dt><dd><b>${rate(rx)}</b></dd><dt>Upload now</dt><dd><b>${rate(tx)}</b></dd>
  <dt>Program file</dt><dd class="mono">${esc(a.exe||a.comm||"Unknown")}</dd>
  ${procs.length===1?`<dt>Command</dt><dd class="mono" style="font-size:11.5px">${esc(a.cmd||"Unknown")}</dd>`:""}
  <dt>Listening</dt><dd>${esc([...new Set(procs.flatMap(p=>p.listening))].join(", ")||"No")}</dd></dl>
  <div class="crow"><button class="btn" data-copy="${pids.join(" ")}" data-copy-label="PIDs">${ic("copy")}Copy PIDs</button><button class="btn" data-copy="${esc(procs.map(p=>p.pid+"  "+p.cmd).join("\n"))}" data-copy-label="command lines">${ic("copy")}Copy command lines</button></div>
  ${procs.length>1?`<div class="sheet"><div class="shead"><h2>Processes</h2></div>${table([{k:"p",label:"PID",r:1,render:p=>`<span class="pid">${p.pid}</span>`},{k:"r",label:"Role",render:p=>esc(p.role||p.comm)},{k:"c",label:"Connections",r:1,render:p=>p.conns},{k:"d",label:"Down",r:1,render:p=>rate(p.rx_rate)},{k:"u",label:"Up",r:1,render:p=>rate(p.tx_rate)}],procs,{tall:1})}</div>`:""}
  <div class="sheet"><div class="shead"><h2>Connections</h2><span class="hint">${socks.length} sockets</span></div>${table([
   {k:"pid",label:"PID",r:1,render:s=>`<span class="pid">${s.pid}</span>`},
   {k:"st",label:"State",render:s=>`${esc(s.proto.toUpperCase())} <span class="muted">${esc(s.state==="ESTAB"?"open":s.state.toLowerCase())}</span>`},
   {k:"peer",label:"Remote",render:s=>s.peer==="*:*"||/^(0\.0\.0\.0|\[::\]|\*):/.test(s.peer)?`<span class="muted">Listening on ${esc(s.local)}</span>`:`${s.peer_name?esc(short(s.peer_name,38))+"<br>":""}<span class="mono${s.peer_name?" muted":""}">${esc(s.peer)}</span>`},
   {k:"rx",label:"Received",r:1,render:s=>s.rx!=null?bytes(s.rx):'<span class="muted">n/a</span>'},
   {k:"tx",label:"Sent",r:1,render:s=>s.tx!=null?bytes(s.tx):'<span class="muted">n/a</span>'}],socks,{tall:1,row:s=>` tabindex="0" data-menu="sock" data-ip="${esc((s.peer||"").replace(/:[^:]*$/,"").replace(/[\[\]]/g,""))}" data-name="${esc(s.peer_name||"")}"`})}</div>`;
 if(live){dr.innerHTML=html;dr.scrollTop=top}else openDrawer(html)}

/* ---------- wifi ---------- */
const sigWord=d=>d>=-55?"Excellent":d>=-67?"Good":d>=-75?"Fair":"Weak";
async function loadWifi(){try{S.wifi=await api("/api/wifi");renderWifi()}catch(e){fail("#wifi",e)}}

/* ---------- VLAN & segment ---------- */
async function loadVlan(){try{S.vlan=await api("/api/vlan");renderVlan()}catch(e){fail("#vlan",e)}}
function renderVlan(){const v=S.vlan;if(!v)return;S.rerender.vlan=renderVlan;
 const h=S.health,st=nm=>(h?.checks||[]).find(c=>c.name===nm)?.status;
 const gwOk=[st("Gateway ping"),st("Gateway ARP")].includes("pass"),netOk=st("Internet by IP")==="pass";
 const chip=(ok,on,off)=>`<span class="tag ${ok?"ok":"warn"}">${ok?on:off}</span>`;
 let access=h?`<div style="margin-bottom:10px">Segment access: ${chip(gwOk,"gateway reachable","gateway not answering")} ${chip(netOk,"internet reachable","no internet")}</div>`:"";
 let body;
 if(v.tagged&&v.tagged.length){
  body=`<div class="soft" style="margin-bottom:8px">This host has 802.1Q VLAN interface${v.tagged.length>1?"s":""} configured:</div>`+
   table([{k:"n",label:"Interface",render:x=>`<span class="mono">${esc(x.name)}</span>`},
    {k:"id",label:"VLAN ID",render:x=>`<span class="tag ok">${esc(String(x.id))}</span>`},
    {k:"p",label:"On NIC",render:x=>`<span class="mono">${esc(x.parent||"?")}</span>`},
    {k:"pr",label:"Tagging",render:x=>esc(x.protocol||"802.1Q")}],v.tagged,{id:"vlantbl"});
 }else{
  body=`<div class="note">${ic("info")}<div>This host sees no 802.1Q VLAN tag. Either you are on an untagged (access) port, or this NIC is not doing VLAN tagging. On an access port the switch removes the tag before the frame reaches you, so the host cannot read the VLAN number on its own. Use <b>Listen for a switch</b> to learn the port or native VLAN from LLDP or CDP, if the switch advertises it.</div></div>`;
 }
 let hint="";
 if(!v.lldp_supported)hint=`<div class="soft" style="margin-top:8px">LLDP/CDP listening needs either lldpd installed or NetPane running as ${v.platform==="windows"?"administrator with lldpd":"root"}.</div>`;
 $("#vlan").innerHTML=access+body+`<div id="lldpout" style="margin-top:10px"></div>`+hint;
 const b=$("#lldpbtn");if(b)b.disabled=!v.lldp_supported}
async function listenLldp(b){const out=$("#lldpout");if(b)b.disabled=true;
 if(out)out.innerHTML=`<div class="loading">Listening for a switch advertisement. This can take up to a minute.</div>`;
 try{const r=await api("/api/lldp?t=65");
  if(!r.ok){if(out)out.innerHTML=`<div class="note">${ic("alert")}<div>${esc(r.reason||"Could not listen.")}</div></div>`;return}
  if(!r.neighbors||!r.neighbors.length){if(out)out.innerHTML=`<div class="note">${ic("info")}<div>${esc(r.note||"No switch advertisement was heard.")}</div></div>`;return}
  const row=x=>{const bits=[];
    if(x.pvid!=null)bits.push(`<span class="tag ok">Port VLAN ${esc(String(x.pvid))}</span>`);
    if(x.native_vlan!=null)bits.push(`<span class="tag ok">Native VLAN ${esc(String(x.native_vlan))}</span>`);
    (x.vlans||[]).forEach(vl=>bits.push(`<span class="chip">VLAN ${esc(String(vl.id))} ${esc(vl.name||"")}</span>`));
    return `<div class="sheet" style="margin-top:8px"><div class="sbody"><dl class="dl">
     <dt>Heard over</dt><dd>${esc(x.proto)}${x.iface?" on "+esc(x.iface):""}</dd>
     <dt>Switch</dt><dd>${esc(x.system||"not advertised")}</dd>
     <dt>Switch port</dt><dd class="mono">${esc(x.port||x.port_descr||"not advertised")}</dd>
     <dt>VLAN</dt><dd>${bits.length?bits.join(" "):"not advertised"}</dd></dl></div></div>`};
  if(out)out.innerHTML=`<div class="soft">Learned from ${esc(r.source==="lldpctl"?"lldpd":"a live capture")}:</div>`+r.neighbors.map(row).join("")}
 catch(e){if(out)out.innerHTML=`<div class="note">${ic("alert")}<div>${esc(e.message)}</div></div>`}
 finally{if(b)b.disabled=false}}

/* ---------- Lookups (intel) ---------- */
async function runLookup(kind){const t=($("#lktarget").value||"").trim();if(!t){toast("Enter a target first");$("#lktarget").focus();return}
 const titles={dns:"DNS records",whois:"WHOIS",rdap:"RDAP",tls:"TLS certificate",asn:"ASN / BGP",exposure:"Public exposure"};
 $("#lkresult").hidden=false;$("#lktitle").textContent=titles[kind];$("#lksub").textContent=t;
 $("#lkbody").innerHTML=`<div class="loading">Looking up ${esc(t)}</div>`;
 $("#lkresult").scrollIntoView({behavior:"smooth",block:"nearest"});
 try{const r=await api("/api/lookup?kind="+kind+"&target="+encodeURIComponent(t));renderLookup(kind,r)}
 catch(e){$("#lkbody").innerHTML=`<div class="note">${ic("alert")}<div>${esc(e.message)}</div></div>`}}
function renderLookup(kind,r){const el=$("#lkbody");
 if(r.error){el.innerHTML=`<div class="note">${ic("alert")}<div>${esc(r.error)}</div></div>`;return}
 const dl=rows=>`<dl class="dl">${rows.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
 const m=t=>`<span class="mono">${esc(t)}</span>`;
 if(kind==="dns"){
  const sets=r.records||{},order=["A","AAAA","NS","MX","SOA","TXT","CAA"];
  let html=`<div class="soft" style="margin-bottom:8px">Resolver: ${m(r.resolver)}</div>`;
  const mail=r.mail||{};
  html+=dl([["SPF",mail.spf?m(mail.spf):`<span class="tag warn">none</span>`],["DMARC",mail.dmarc?m(mail.dmarc):`<span class="tag warn">none</span>`]]);
  const got=order.filter(k=>sets[k]&&sets[k].length);
  if(got.length)html+=got.map(k=>`<div style="margin-top:8px"><b>${k}</b><div>${sets[k].map(m).join("<br>")}</div></div>`).join("");
  else html+=`<div class="soft" style="margin-top:8px">No records returned (the resolver may filter, or the name may not exist).</div>`;
  el.innerHTML=html;return}
 if(kind==="whois"||kind==="asn"&&r.raw){
  if(kind==="whois"){el.innerHTML=`<div class="soft" style="margin-bottom:6px">Server: ${m(r.server)}</div><pre class="term" style="min-height:0">${esc(r.text||"")}</pre>`;return}}
 if(kind==="asn"){el.innerHTML=dl([["AS number",`<span class="tag ok">AS${esc(r.asn)}</span>`],["AS name",esc(r.as_name||"")],["BGP prefix",m(r.prefix||"")],["Country",esc(r.country||"")],["Registry",esc((r.registry||"").toUpperCase())],["Allocated",esc(r.allocated||"")]]);return}
 if(kind==="rdap"){const rows=[["Handle",m(r.handle||"-")],["Name",esc(r.name||"-")]];
  if(r.range)rows.push(["Range",m(r.range)]);if(r.country)rows.push(["Country",esc(r.country)]);
  if(r.status&&r.status.length)rows.push(["Status",r.status.map(s=>`<span class="chip">${esc(s)}</span>`).join(" ")]);
  (r.events||[]).forEach(e=>rows.push([esc(e.action),esc((e.date||"").replace("T"," ").slice(0,19))]));
  (r.entities||[]).slice(0,8).forEach(en=>rows.push([esc((en.roles||[]).join(", ")||"entity"),esc(en.name||"")]));
  el.innerHTML=dl(rows);return}
 if(kind==="tls"){if(r.note&&!r.subject){el.innerHTML=`<div class="note">${ic("info")}<div>${esc(r.note)}</div></div>`;return}
  const dleft=r.days_left,chip=dleft==null?"":dleft<0?`<span class="tag fail">expired ${-dleft}d ago</span>`:dleft<=30?`<span class="tag warn">${dleft} days left</span>`:`<span class="tag ok">${dleft} days left</span>`;
  const rows=[["Subject",esc(r.subject||"-")],["Issuer",esc(r.issuer||"-")],["Valid from",m(r.valid_from||"")],["Valid to",`${m(r.valid_to||"")} ${chip}`],["Protocol",esc(r.proto||"")+(r.cipher?" · "+esc(r.cipher):"")],["SAN count",esc(String(r.san_count||0))]];
  let html=dl(rows);
  if(r.sans&&r.sans.length)html+=`<div style="margin-top:8px"><b>Subject alternative names</b><div class="soft" style="margin-top:4px">${r.sans.map(s=>`<span class="chip">${esc(s)}</span>`).join(" ")}</div></div>`;
  el.innerHTML=html;return}
 if(kind==="exposure"){const rows=[["IP",m(r.ip||"")]];
  rows.push(["Open ports",(r.ports&&r.ports.length)?r.ports.map(p=>`<span class="chip">${esc(String(p))}</span>`).join(" "):"none indexed"]);
  if(r.hostnames&&r.hostnames.length)rows.push(["Hostnames",r.hostnames.map(m).join("<br>")]);
  if(r.tags&&r.tags.length)rows.push(["Tags",r.tags.map(t=>`<span class="chip">${esc(t)}</span>`).join(" ")]);
  if(r.vulns&&r.vulns.length)rows.push(["Known CVEs",r.vulns.map(v=>`<span class="tag warn">${esc(v)}</span>`).join(" ")]);
  let html=dl(rows);if(r.note)html+=`<div class="soft" style="margin-top:8px">${esc(r.note)}</div>`;
  el.innerHTML=html;return}
 el.innerHTML=`<pre class="term" style="min-height:0">${esc(JSON.stringify(r,null,2))}</pre>`}
function renderWifi(){const w=S.wifi||{networks:[]},cur=(S.ov?.interfaces||[]).filter(i=>i.wireless);
 if(!cur.length&&!w.networks.length){$("#wifi").innerHTML=`<div class="empty">This computer has no Wi-Fi adapter.</div>`;return}
 let x=cur.map(i=>`<div class="sbody"><dl class="dl" style="margin:0"><dt>${esc(i.name)}</dt><dd>${i.wifi&&i.wifi.ssid?`<b>${esc(i.wifi.ssid)}</b>, ${i.wifi.signal_pct!=null?esc(i.wifi.signal_pct)+"% signal":esc(i.wifi.signal)+" dBm"} (${sigWord(i.wifi.signal)}), ${esc(i.wifi.freq?(/\d$/.test(i.wifi.freq)?i.wifi.freq+" MHz":i.wifi.freq):"")}${i.wifi.channel?", channel "+esc(i.wifi.channel):""}, ${esc(i.wifi.bitrate||"")}`:'<span class="tag warn">Not connected</span>'}</dd></dl></div>`).join("");
 if(w.networks.length){const ch=count(w.networks,n=>n.chan);S.rerender.wifi=renderWifi;
  x+=table([{k:"s",label:"Network",sort:n=>n.ssid,render:n=>`${n.inuse?'<span class="led ok" style="margin-right:8px"></span>':""}${esc(n.ssid||"Hidden network")}`},{k:"c",label:"Channel",r:1,sort:n=>+n.chan||0,render:n=>esc(n.chan)},{k:"g",label:"Signal",r:1,sort:n=>n.signal,render:n=>`${esc(n.signal)}%`},{k:"sec",label:"Security",sort:n=>n.security,render:n=>esc(n.security)}],w.networks.slice(0,20),{id:"wifi",sort:{k:"g",dir:"desc"},tall:1});
  x+=`<div class="sbody muted" style="font-size:12px">Most crowded channels: ${ch.slice(0,4).map(c=>`${esc(c[0])} (${c[1]} networks)`).join(", ")}</div>`}
 else if(w.note)x+=`<div class="note info">${ic("info")}<div>${esc(w.note)}</div></div>`;
 $("#wifi").innerHTML=x}

/* ---------- tools & console ---------- */
async function loadTools(){try{const t=await api("/api/tools");S.tools=t.tools;renderTools(t);fillConsole()}catch(e){fail("#tools",e)}}
function renderTools(t){$("#tcount").textContent=`${t.installed} of ${t.tools.length} installed`;
 const cats={};t.tools.forEach(x=>(cats[x.category]=cats[x.category]||[]).push(x));
 let x=t.install_cmd?`<div class="sbody" style="padding-bottom:2px"><div class="soft">${esc(t.install_hint)}</div><div class="copy"><code>${esc(t.install_cmd)}</code><button class="btn sm" data-copy="${esc(t.install_cmd)}" data-copy-label="install command">Copy</button></div></div>`:"";
 x+=Object.entries(cats).map(([c,a])=>`<div class="ghead" style="padding-top:12px">${esc(c)}</div><div class="toolgrid">${a.map(i=>`<div class="tool ${i.installed?"on":"off"}">${ic(i.installed?"check":"x")}<div><b>${esc(i.cmd)}</b><div>${esc(i.desc)}</div></div></div>`).join("")}</div>`).join("");
 $("#tools").innerHTML=x}
function fillConsole(){const sel=$("#ctool"),cur=sel.value;
 sel.innerHTML=S.tools.map(t=>`<option value="${esc(t.cmd)}"${t.installed?"":" disabled"}>${esc(t.cmd)}${t.installed?"":" (not installed)"}</option>`).join("");
 const first=S.tools.find(t=>t.installed);sel.value=cur&&S.tools.find(t=>t.cmd===cur&&t.installed)?cur:(first?first.cmd:"");showPresets()}
function vars(){const o=S.ov||{},dev=o.primary||"eth0",me=(o.interfaces||[]).find(i=>i.name===dev);
 return {gw:o.gateway?.gateway||"192.168.1.1",dev,net:S.neigh?.network||(me&&me.ipv4[0])||"192.168.1.0/24"}}
function showPresets(){const t=$("#ctool").value,v=vars();
 $("#cpresets").innerHTML=(((S.tools||[]).find(x=>x.cmd===t)||{}).presets||[]).map(p=>{const a=p.replace(/\{(\w+)\}/g,(_,k)=>v[k]);return `<button data-preset="${esc(a)}">${esc((t+" "+a).trim())}</button>`}).join("")}
async function runTool(tool,args){const r=await api("/api/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tool,args})});
 return `$ ${r.cmd}\n${r.out||""}${r.err?(r.out?"\n":"")+r.err:""}\n[exit ${r.rc}, ${r.seconds}s]`}
async function consoleRun(){const t=$("#ctool").value,a=$("#cargs").value,o=$("#cout");if(!t)return;
 const before=o.dataset.used?o.textContent+"\n\n":"";o.dataset.used=1;
 $("#crun").disabled=true;o.textContent=before+`$ ${t} ${a}\nRunning…`;o.scrollTop=o.scrollHeight;
 try{o.textContent=before+await runTool(t,a)}catch(e){o.textContent=before+`$ ${t} ${a}\n${e.message}`}
 $("#crun").disabled=false;o.scrollTop=o.scrollHeight}

/* ---------- traffic ---------- */
async function pollTraffic(){try{S.traffic=await api("/api/traffic");const names=Object.keys(S.traffic),sel=$("#tiface");
  if(sel.options.length!==names.length)sel.innerHTML=names.map(n=>`<option>${esc(n)}</option>`).join("");
  if(!S.tif||!S.traffic[S.tif])S.tif=names[0];sel.value=S.tif;
  const pr=S.traffic[S.ov?.primary||S.tif]||[],l=pr[pr.length-1];
  if(l)$("#sb-rate").innerHTML=`<span style="color:var(--rx)">↓</span>${rate(l[1])}&nbsp;&nbsp;<span style="color:var(--tx)">↑</span>${rate(l[2])}`;
  if(S.view==="traffic")drawChart()}catch(e){$("#sb-rate").textContent=""}}
function drawChart(){const c=$("#tchart");if(!c||!c.clientWidth)return;const d=(S.traffic||{})[S.tif]||[],dpr=window.devicePixelRatio||1,w=c.clientWidth,h=300;
 const cs=getComputedStyle(document.documentElement),V=k=>cs.getPropertyValue(k).trim();
 c.width=w*dpr;c.height=h*dpr;const x=c.getContext("2d");x.scale(dpr,dpr);x.clearRect(0,0,w,h);
 const max=Math.max(1250,...d.map(p=>Math.max(p[1],p[2])))*1.15,N=120,top=6,bh=h-26;
 x.font="11px "+V("--sans");x.lineWidth=1;
 for(let i=0;i<=4;i++){const y=top+bh*i/4;x.strokeStyle=V("--line-2");x.beginPath();x.moveTo(0,y+.5);x.lineTo(w,y+.5);x.stroke();x.fillStyle=V("--ink-3");if(i<4)x.fillText(rate(max*(1-i/4)),2,y+13)}
 x.fillStyle=V("--ink-3");x.fillText("2 min ago",2,h-6);x.textAlign="right";x.fillText("now",w-2,h-6);x.textAlign="left";
 const line=(k,col)=>{if(!d.length)return;x.strokeStyle=col;x.lineWidth=2;x.lineJoin="round";x.beginPath();d.forEach((p,i)=>{const px=w-(d.length-1-i)*(w/(N-1)),py=top+bh*(1-p[k]/max);i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke()};
 line(1,V("--rx"));line(2,V("--tx"));
 const last=d[d.length-1],pk=d.reduce((m,p)=>Math.max(m,p[1],p[2]),0);
 $("#tnow").innerHTML=`<div class="meter"><dt><span class="sw" style="background:var(--rx)"></span>Download</dt><dd>${last?rate(last[1]):"…"}</dd></div><div class="meter"><dt><span class="sw" style="background:var(--tx)"></span>Upload</dt><dd>${last?rate(last[2]):"…"}</dd></div><div class="meter"><dt>Peak, last 2 minutes</dt><dd>${rate(pk)}</dd></div>`}

/* ---------- context menu ---------- */
function ctxItems(el){const m=el.dataset.menu,ip=el.dataset.ip,mac=el.dataset.mac,name=el.dataset.name,pids=el.dataset.pids,port=el.dataset.port,items=[];
 if(m==="device"){items.push(["open","Show details",()=>showHost(ip)],["play","Ping",()=>{showHost(ip);hostAction(ip,"ping")}],["search","Scan ports",()=>{showHost(ip);hostAction(ip,"scan")}],["path","Trace path to here",()=>{go("path");loadPath(ip)}],"-",["copy","Copy IP address",()=>copy(ip,"IP address")]);if(mac)items.push(["copy","Copy hardware address",()=>copy(mac,"hardware address")]);if(name)items.push(["copy","Copy name",()=>copy(name,"name")])}
 else if(m==="app"){if(el.dataset.app)items.push(["open","Show connections",()=>showApp(el.dataset.app)]);items.push(["copy",pids.includes(" ")?"Copy PIDs":"Copy PID",()=>copy(pids,pids.includes(" ")?"PIDs":"PID "+pids)],["copy","Copy name",()=>copy(name,"name")]);if(port)items.push(["copy","Copy port",()=>copy(port,"port "+port)]);items.push("-",["search","Filter Apps by this",()=>{go("apps");$("#afilter").value=name;renderApps()}])}
 else if(m==="hop"||m==="sock"){if(ip)items.push(["path","Trace path to here",()=>{closeDrawer();go("path");loadPath(ip)}],["copy","Copy address",()=>copy(ip,"address")]);if(name)items.push(["copy","Copy name",()=>copy(name,"name")])}
 return items}
function openCtx(el,x,y){const items=ctxItems(el);if(!items.length)return;const m=$("#ctx");S.ctxFns=[];
 m.innerHTML=items.map(it=>it==="-"?"<hr>":(S.ctxFns.push(it[2]),`<button role="menuitem" data-ctxi="${S.ctxFns.length-1}">${ic(it[0])}${esc(it[1])}</button>`)).join("");
 m.hidden=false;const r=m.getBoundingClientRect();m.style.left=Math.min(x,innerWidth-r.width-6)+"px";m.style.top=Math.min(y,innerHeight-r.height-6)+"px";m.querySelector("button").focus()}
function closeCtx(){$("#ctx").hidden=true}
document.addEventListener("contextmenu",e=>{if(e.target.closest("input,textarea,.term,pre,dd,code"))return;e.preventDefault();const el=e.target.closest("[data-menu]");if(el)openCtx(el,e.clientX,e.clientY);else closeCtx()});
$("#ctx").addEventListener("click",e=>{const b=e.target.closest("[data-ctxi]");if(!b)return;closeCtx();S.ctxFns[+b.dataset.ctxi]()});

/* ---------- clicks & keys ---------- */
document.addEventListener("click",e=>{
 if(!e.target.closest("#ctx"))closeCtx();
 const nav=e.target.closest("[data-go]");if(nav){go(nav.dataset.go);return}
 const cl=e.target.closest("[data-close]");if(cl){closeDrawer();return}
 const cp=e.target.closest("[data-copy]");if(cp){copy(cp.dataset.copy,cp.dataset.copyLabel);return}
 const ap=e.target.closest("[data-app]");if(ap){showApp(ap.dataset.app);return}
 const hb=e.target.closest("[data-host]");if(hb){showHost(hb.dataset.host);return}
 const sn=e.target.closest("[data-stage]");if(sn){const g=$("#g-"+sn.dataset.stage);if(g){g.scrollIntoView({behavior:"smooth",block:"center"});g.classList.remove("flash");void g.offsetWidth;g.classList.add("flash")}return}
 const gb=e.target.closest("[data-group]");if(gb){S.group=gb.dataset.group;$$("[data-group]").forEach(b=>b.setAttribute("aria-pressed",b===gb));renderApps();return}
 const p=e.target.closest("[data-preset]");if(p){$("#cargs").value=p.dataset.preset;consoleRun()}});
document.addEventListener("keydown",e=>{
 const k=e.key,mod=e.ctrlKey||e.metaKey,typing=e.target.matches("input,textarea,select");
 if(k==="Escape"){if(!$("#keys").hidden){$("#keys").hidden=true;return}if(!$("#ctx").hidden){closeCtx();return}if(!$("#scrim").hidden){closeDrawer();return}if(typing)e.target.blur();return}
 if((mod&&k.toLowerCase()==="r")||k==="F5"){e.preventDefault();runAll();return}
 if(mod&&k.toLowerCase()==="s"){e.preventDefault();location.href="/api/report.txt";toast("Saving the text report");return}
 if(mod&&/^[1-8]$/.test(k)){e.preventDefault();go(VIEWS[+k-1]);return}
 if(mod&&k.toLowerCase()==="f"||(!typing&&k==="/")){const f=$("#bartools [data-filter]");if(f){e.preventDefault();f.focus();f.select&&f.select()}return}
 if(!typing&&(k==="?"||k==="F1")){e.preventDefault();$("#keys").hidden=!$("#keys").hidden;return}
 if(!$("#ctx").hidden&&(k==="ArrowDown"||k==="ArrowUp")){e.preventDefault();const bs=$$("#ctx button"),i=bs.indexOf(document.activeElement);bs[(i+(k==="ArrowDown"?1:-1)+bs.length)%bs.length].focus();return}
 const row=e.target.closest&&e.target.closest("tr[tabindex]");
 if(row){if(k==="ArrowDown"||k==="ArrowUp"){e.preventDefault();let n=k==="ArrowDown"?row.nextElementSibling:row.previousElementSibling;while(n&&!n.hasAttribute("tabindex"))n=k==="ArrowDown"?n.nextElementSibling:n.previousElementSibling;if(n)n.focus()}
  else if(k==="Enter"){e.preventDefault();row.click()}
  else if((e.shiftKey&&k==="F10")||k==="ContextMenu"){e.preventDefault();const r=row.getBoundingClientRect();openCtx(row,r.left+40,r.bottom-4)}}});
$("#sb-health").onclick=()=>go("diagnosis");$("#sb-keys").onclick=()=>$("#keys").hidden=false;$("#keys").onclick=e=>{if(e.target.id==="keys")$("#keys").hidden=true};

/* ---------- lifecycle ---------- */
async function runAll(){const b=$("#runall");if(b.disabled)return;b.disabled=true;b.querySelector("span").textContent="Checking…";
 await loadOverview();loadWifi();loadTools();
 const [h,n]=await Promise.all([loadHealth(),loadNeighbors(),loadPath()]);
 b.disabled=false;b.querySelector("span").textContent="Run checks";
 if(h){const v=h.verdict;toast(v.status==="pass"?"All clear. The network is healthy end to end.":v.headline,CLS[v.status])}}
$("#runall").onclick=runAll;$("#rescan").onclick=async()=>{const n=await loadNeighbors();if(n&&!n.error)toast(`Found ${n.count} ${n.count===1?"device":"devices"} on ${n.network}`)};
$("#nfilter").oninput=renderNeigh;$("#afilter").oninput=renderApps;
$("#alive").onchange=()=>{if($("#alive").checked){stopApps();startApps()}};
$("#pathf").onsubmit=e=>{e.preventDefault();loadPath()};
$("#tiface").onchange=e=>{S.tif=e.target.value;drawChart()};
$("#ctool").onchange=showPresets;$("#crun").onclick=consoleRun;$("#cclear").onclick=()=>{$("#cout").textContent="";delete $("#cout").dataset.used};
$("#cargs").onkeydown=e=>{if(e.key==="Enter")consoleRun()};
$("#lldpbtn").onclick=e=>listenLldp(e.currentTarget);
$$("[data-lk]").forEach(b=>b.onclick=()=>runLookup(b.dataset.lk));
$("#lktarget").onkeydown=e=>{if(e.key==="Enter")runLookup("dns")};
window.addEventListener("hashchange",()=>go(location.hash.slice(1)));
window.addEventListener("resize",()=>{if(S.view==="traffic")drawChart()});
matchMedia("(prefers-color-scheme: dark)").addEventListener("change",()=>setTheme(document.documentElement.dataset.theme));
const PAGE=Math.random().toString(36).slice(2);
const hello=()=>fetch("/api/hello?id="+PAGE).catch(()=>{});hello();setInterval(hello,20000);
window.addEventListener("pagehide",()=>{try{navigator.sendBeacon("/api/bye",new Blob([PAGE],{type:"text/plain"}))}catch(e){}});
setInterval(pollTraffic,1000);
setInterval(()=>{if($("#auto").checked){loadHealth();if(S.view==="apps")loadApps()}},60000);
setTheme(document.documentElement.dataset.theme);go(location.hash.slice(1)||"diagnosis");renderVerdictWaiting();renderFacts();
runAll();
</script></body></html>
"""

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        if getattr(sys, "frozen", False):
            input("\nNetPane hit an error. Press Enter to close this window.")
