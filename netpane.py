#!/usr/bin/env python3
"""
NetPane: a single pane of glass for Linux network troubleshooting.

Run it:      sudo python3 netpane.py
Then open:   http://127.0.0.1:8765   (opens automatically)

Root is optional but unlocks arping, tcpdump, nethogs, iftop and process names
on every socket. Only the Python 3 standard library is required. Every external
tool (ip, ss, fping, nmap, mtr, dig, ...) is used when present and skipped when not.
"""

import argparse
import collections
import concurrent.futures as cf
import datetime as dt
import importlib.util
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import textwrap
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.1.0"
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
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


def have(binary):
    return shutil.which(binary) is not None


def run(cmd, timeout=15):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    if not cmd or not have(cmd[0]):
        return {"ok": False, "rc": 127, "out": "", "err": f"{cmd[0] if cmd else '?'} is not installed"}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=ENV, stdin=subprocess.DEVNULL)
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
TOOLS = [
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
    ("avahi-resolve-address", "avahi-utils", "Names", "mDNS names for neighbours"),
    ("nmblookup", "samba-common-bin", "Names", "NetBIOS names for Windows neighbours"),
]


def tool_inventory():
    tools = [{"cmd": c, "package": p, "category": cat, "desc": d,
              "installed": have(c), "path": shutil.which(c) or ""} for c, p, cat, d in TOOLS]
    libs = [{"name": n, "installed": importlib.util.find_spec(m) is not None}
            for n, m in (("scapy", "scapy"), ("psutil", "psutil"))]
    missing = sorted({t["package"] for t in tools if not t["installed"]})
    return {"tools": tools, "libs": libs, "installed": sum(t["installed"] for t in tools),
            "install_cmd": ("sudo apt install -y " + " ".join(missing)) if missing else ""}


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
    r4 = run_json(["ip", "-j", "route"]) or []
    r6 = run_json(["ip", "-j", "-6", "route"]) or []
    gws = [{"gateway": r.get("gateway"), "dev": r.get("dev"), "metric": r.get("metric", 0),
            "proto": r.get("protocol")} for r in r4 if r.get("dst") == "default" and r.get("gateway")]
    gws.sort(key=lambda g: g["metric"] or 0)
    return {"ipv4": r4, "ipv6": r6, "gateways": gws}


def dns_info():
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
        "hostname": socket.gethostname(), "fqdn": socket.getfqdn(), "kernel": os.uname().release,
        "user": os.environ.get("SUDO_USER") or os.environ.get("USER", ""), "root": IS_ROOT,
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
    if have("avahi-resolve-address"):
        r = run(["avahi-resolve-address", ip], 3)
        parts = r["out"].split()
        if r["ok"] and len(parts) >= 2:
            return parts[1], "mDNS"
    if have("nmblookup"):
        for line in run(["nmblookup", "-A", ip], 3)["out"].splitlines():
            m = re.match(r"\s*(\S+)\s+<00>\s+-\s+(?!<GROUP>)", line)
            if m:
                return m.group(1), "NetBIOS"
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
        if have("fping"):
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
    for n in run_json(["ip", "-j", "neigh", "show", "dev", dev]) or []:
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
# probes used by the health check
# --------------------------------------------------------------------------
def parse_ping(out):
    loss = re.search(r"([\d.]+)% packet loss", out)
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    return {"loss": float(loss.group(1)) if loss else 100.0,
            "min": float(rtt.group(1)) if rtt else None, "avg": float(rtt.group(2)) if rtt else None,
            "max": float(rtt.group(3)) if rtt else None, "mdev": float(rtt.group(4)) if rtt else None}


def ping(host, count=4):
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
    t0 = time.time()
    r = run(["dig", "+time=2", "+tries=1", "+short", f"@{server}", name, "A"], 6)
    ms = round((time.time() - t0) * 1000)
    ips = [l for l in r["out"].split() if re.match(r"^\d+\.\d+\.\d+\.\d+$", l)]
    err = "" if ips else ((r["out"].strip().splitlines() or [r["err"].strip() or "no answer"])[-1])[:90]
    return {"ok": bool(ips), "ms": ms, "err": err}


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
    return {"full": False, "mtu": mtu, "iface_mtu": local, "pmtud": reported is not None,
            "reported": reported}


def gateway_arp(gw, dev):
    if IS_ROOT and have("arping"):
        r = run(["arping", "-c", "2", "-w", "3", "-I", dev, gw], 6)
        if r["ok"]:
            m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", r["out"])
            return True, f"Gateway {gw} answered ARP{(' from ' + m.group(1)) if m else ''}."
    for e in run_json(["ip", "-j", "neigh", "show", gw]) or []:
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
                       "Run: ethtool <iface> and ip link to confirm."]),
    "IP address": ("IP addressing (DHCP)",
                   "The link is up but this host never got a usable IPv4 address.",
                   ["Confirm the DHCP server is up and the scope is not exhausted.",
                    "Check the switch port is on the right VLAN.",
                    "Retry: sudo dhclient -v <iface> or nmcli con up <name>.",
                    "Set a static IP temporarily to prove the segment works."]),
    "Default route": ("this machine's routing setup",
                      "There is no default gateway, so only the local subnet is reachable.",
                      ["Check DHCP option 3 (router) or the static config.",
                       "Add one to test: sudo ip route add default via <gateway-ip>."]),
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
                    "Check the host firewall: sudo iptables -L -n or sudo nft list ruleset."]),
    "MTU / fragmentation": ("an MTU mismatch on the path",
                            "Full-size packets are being dropped.",
                            ["Common with VPNs, PPPoE and tunnels.",
                             "Lower the interface MTU to the exact value found, or enable TCP MSS clamping (MTU minus 40) on the router."]),
    "DNS servers": ("DNS",
                    "None of the configured DNS servers answered.",
                    ["Check the DNS server or forwarder is running.",
                     "Test a public resolver: dig @1.1.1.1 google.com.",
                     "Check UDP/TCP 53 is allowed outbound."]),
    "Name resolution": ("name lookups on this machine",
                        "The internet works by IP, but names do not resolve.",
                        ["Check /etc/resolv.conf and systemd-resolved: resolvectl status.",
                         "Try a public resolver to confirm: dig @1.1.1.1 google.com."]),
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
    if have("dig"):
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
                                 "Check the cable or Wi-Fi, then run: ip link")
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
                                 "Check DHCP option 3 or add: sudo ip route add default via <gw>")
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
                                           f"Test now: sudo ip link set dev {dev} mtu {m}. If that fixes it, make it permanent with "
                                           f"nmcli con mod \"<connection>\" 802-3-ethernet.mtu {m} (use 802-11-wireless.mtu on Wi-Fi), "
                                           f"or better, enable TCP MSS clamping to {mss} on the router so every device is fixed.")
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
                               "Set DNS via DHCP, NetworkManager or resolv.conf.")
    elif not have("dig"):
        res["DNS servers"] = C("DNS servers", "skip",
                               f"Configured: {', '.join(servers)}. Install dnsutils (dig) to test each server on its own.")
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
                                   "Check resolv.conf / resolvectl status, or test dig @1.1.1.1 google.com")
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
# path trace, sockets, wifi, traffic
# --------------------------------------------------------------------------
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]{0,252}$")


def path(target):
    if not HOST_RE.match(target or ""):
        return {"error": "Invalid target", "hops": []}
    hops, method = [], ""
    if have("mtr"):
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
        return remember("path", {"target": target, "error": "No path tool worked here. Install mtr or traceroute.", "hops": []})
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
    r = run(["ss", "-H", "-tunap"], 10)
    rows = []
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
    note = "" if IS_ROOT else "Not running as root, so process names for other users' sockets are hidden."
    if not rows and not r["ok"]:
        note = r["err"]
    return remember("sockets", {"all": rows[:3000], "listening": listening, "established": established[:1500], "note": note})


def wifi_scan():
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
        return {k: list(v) for k, v in TRAFFIC.items() if k != "lo"}


# --------------------------------------------------------------------------
# console: run any of the tools with safe bounds
# --------------------------------------------------------------------------
CONSOLE_TIMEOUT = {"nmap": 180, "traceroute": 90, "mtr": 90, "tcpdump": 60, "tshark": 60, "ngrep": 60,
                   "iperf3": 60, "whois": 30, "lshw": 60}


def _has(args, *flags):
    for a in args:
        for f in flags:
            if a == f or (len(f) == 2 and a.startswith(f) and not a.startswith("--")):
                return True
    return False


def guard(tool, a):
    a = list(a)
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
        args = shlex.split(argstr or "")
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
        self.end_headers()
        self.wfile.write(body)

    def host_ok(self):
        return ALLOW_ANY_HOST or self.headers.get("Host", "") in ALLOWED_HOSTS

    def do_GET(self):
        if not self.host_ok():
            return self.send(403, {"error": "Host not allowed"})
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        simple = {"/api/overview": overview, "/api/health": health, "/api/neighbors": discover,
                  "/api/sockets": sockets, "/api/tools": tool_inventory, "/api/wifi": wifi_scan,
                  "/api/traffic": traffic}
        try:
            if u.path in ("/", "/index.html"):
                return self.send(200, INDEX_HTML, "text/html")
            if u.path in simple:
                return self.send(200, simple[u.path]())
            if u.path == "/api/path":
                return self.send(200, path(q.get("target", "1.1.1.1")))
            if u.path == "/api/scanhost":
                return self.send(200, scan_host(q.get("ip", "")))
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
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self.send(415, {"error": "JSON required"})
        try:
            n = min(int(self.headers.get("Content-Length", 0)), 100000)
            body = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/api/run":
                return self.send(200, console(str(body.get("tool", "")), str(body.get("args", ""))))
            self.send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            self.send(500, {"error": f"{type(e).__name__}: {e}"})


def open_browser(url):
    user, uid = os.environ.get("SUDO_USER"), os.environ.get("SUDO_UID")
    try:
        if IS_ROOT and user and uid and have("sudo") and have("xdg-open"):
            env = [f"{k}={os.environ[k]}" for k in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY") if k in os.environ]
            env += [f"XDG_RUNTIME_DIR=/run/user/{uid}", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"]
            subprocess.Popen(["sudo", "-u", user, "env"] + env + ["xdg-open", url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            webbrowser.open(url)
    except Exception:  # noqa: BLE001
        pass


def main():
    global ALLOW_ANY_HOST
    ap = argparse.ArgumentParser(description="NetPane: single pane of glass network troubleshooter")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--bind", default="127.0.0.1",
                    help="address to listen on (default 127.0.0.1; use 0.0.0.0 to open it to your LAN)")
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser automatically")
    ap.add_argument("--report", action="store_true", help="print a text report to the terminal and exit")
    args = ap.parse_args()

    if args.report:
        overview(); health(); discover(); path("1.1.1.1"); sockets()
        print(text_report())
        return

    for h in ("127.0.0.1", "localhost", "[::1]", args.bind):
        ALLOWED_HOSTS.add(f"{h}:{args.port}")
    if args.bind in ("0.0.0.0", "::"):
        ALLOW_ANY_HOST = True
    threading.Thread(target=sampler, daemon=True).start()
    threading.Thread(target=oui_db, daemon=True).start()
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    url = f"http://{'127.0.0.1' if args.bind in ('0.0.0.0', '::') else args.bind}:{args.port}/"
    print(f"\n  NetPane {VERSION} is running at {url}")
    if not IS_ROOT:
        print("  Tip: start with sudo for arping, tcpdump, nethogs and full process names.")
    if args.bind in ("0.0.0.0", "::"):
        print("  Warning: listening on all interfaces. Anyone who can reach this port can run network tools.")
    print("  Press Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Timer(1.0, open_browser, [url]).start()
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
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect x='2' y='2' width='20' height='20' rx='5' fill='%2315202B'/%3E%3Crect x='5' y='5' width='6' height='6' rx='1.5' fill='%2317914F'/%3E%3Crect x='13' y='5' width='6' height='6' rx='1.5' fill='%23fff' opacity='.35'/%3E%3Crect x='5' y='13' width='6' height='6' rx='1.5' fill='%23fff' opacity='.35'/%3E%3Crect x='13' y='13' width='6' height='6' rx='1.5' fill='%23fff' opacity='.35'/%3E%3C/svg%3E">
<style>
:root{
 --canvas:#EDF0F3;--surface:#FFFFFF;--sunken:#F5F7F9;--hover:#F0F3F6;
 --ink:#15202B;--ink-2:#4A5866;--ink-3:#77838F;--line:#D9DFE5;--line-2:#E8ECF0;
 --ok:#17914F;--warn:#BD7608;--fail:#D33A2C;--idle:#AEB8C2;
 --ok-soft:#E2F3E9;--warn-soft:#FAEFD9;--fail-soft:#FBE5E2;
 --rx:#2F6FEB;--tx:#0E8C87;--focus:#2F6FEB;
 --shadow:0 1px 2px rgba(21,32,43,.06),0 8px 24px rgba(21,32,43,.06);
 --sans:-apple-system,BlinkMacSystemFont,"Segoe UI Variable Text","Segoe UI",Ubuntu,Cantarell,"Noto Sans","Helvetica Neue",Arial,sans-serif;
 --mono:ui-monospace,"SF Mono","Cascadia Mono","Ubuntu Mono","DejaVu Sans Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
 --canvas:#0E151C;--surface:#141D26;--sunken:#1A242E;--hover:#1C2731;
 --ink:#E5EBF0;--ink-2:#A8B5C1;--ink-3:#73818E;--line:#283541;--line-2:#1F2B36;
 --ok:#3CBD74;--warn:#E3A43A;--fail:#F0634F;--idle:#4F5D6A;
 --ok-soft:rgba(60,189,116,.13);--warn-soft:rgba(227,164,58,.14);--fail-soft:rgba(240,99,79,.14);
 --rx:#6A9BFF;--tx:#3CC7C0;--focus:#6A9BFF;--shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.25)}}
:root[data-theme="dark"]{
 --canvas:#0E151C;--surface:#141D26;--sunken:#1A242E;--hover:#1C2731;
 --ink:#E5EBF0;--ink-2:#A8B5C1;--ink-3:#73818E;--line:#283541;--line-2:#1F2B36;
 --ok:#3CBD74;--warn:#E3A43A;--fail:#F0634F;--idle:#4F5D6A;
 --ok-soft:rgba(60,189,116,.13);--warn-soft:rgba(227,164,58,.14);--fail-soft:rgba(240,99,79,.14);
 --rx:#6A9BFF;--tx:#3CC7C0;--focus:#6A9BFF;--shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.25)}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--canvas);color:var(--ink);font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased;font-variant-numeric:tabular-nums}
.i{width:18px;height:18px;flex:none;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
button,input,select{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:6px}
a{color:inherit}
.mono{font-family:var(--mono);font-size:12.5px}
.muted{color:var(--ink-3)}.soft{color:var(--ink-2)}

/* shell */
.app{display:grid;grid-template-columns:232px minmax(0,1fr);min-height:100vh;background:linear-gradient(90deg,var(--surface) 0 231px,var(--line) 231px 232px,transparent 232px)}
.side{background:var(--surface);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;padding:18px 12px}
.brand{display:flex;align-items:center;gap:10px;padding:2px 10px 18px;font-weight:650;font-size:16px;letter-spacing:-.01em}
.brand svg{width:26px;height:26px}
.nav{display:flex;flex-direction:column;gap:2px}
.nav button{display:flex;align-items:center;gap:11px;width:100%;padding:8px 10px;border:0;background:none;border-radius:8px;cursor:pointer;color:var(--ink-2);text-align:left}
.nav button:hover{background:var(--hover);color:var(--ink)}
.nav button[aria-current="page"]{background:var(--sunken);color:var(--ink);font-weight:600}
.nav .count{margin-left:auto;font-size:12px;color:var(--ink-3)}
.nav .led{margin-left:auto}
.side-foot{margin-top:auto;padding:12px 10px 0;border-top:1px solid var(--line-2);font-size:12.5px;color:var(--ink-3);display:flex;flex-direction:column;gap:10px}
.host{color:var(--ink-2)}.host b{color:var(--ink);font-weight:600}
.iconbtn{display:inline-flex;align-items:center;gap:8px;border:0;background:none;color:var(--ink-2);cursor:pointer;padding:4px 0}
.iconbtn:hover{color:var(--ink)}

main{min-width:0}
.bar{display:flex;align-items:center;gap:10px;padding:14px 36px;border-bottom:1px solid var(--line);background:var(--surface);position:sticky;top:0;z-index:5}
.bar .title{font-weight:600;font-size:15px}
.bar .sub{color:var(--ink-3);font-size:13px}
.bar .grow{flex:1}
.btn{display:inline-flex;align-items:center;gap:7px;height:34px;padding:0 13px;border:1px solid var(--line);background:var(--surface);border-radius:8px;cursor:pointer;text-decoration:none;white-space:nowrap;font-weight:500}
.btn:hover{background:var(--hover)}
.btn.primary{background:var(--ink);border-color:var(--ink);color:var(--surface)}
.btn.primary:hover{opacity:.9}
.btn[disabled]{opacity:.55;cursor:progress}
.btn .i{width:16px;height:16px}
.btn.sm{height:28px;padding:0 10px;font-size:13px}
input.field,select.field{height:34px;padding:0 11px;border:1px solid var(--line);border-radius:8px;background:var(--surface);min-width:0}
input.field::placeholder{color:var(--ink-3)}
.switch{display:inline-flex;align-items:center;gap:8px;color:var(--ink-2);font-size:13px;cursor:pointer;user-select:none}
.switch input{appearance:none;width:30px;height:18px;border-radius:9px;background:var(--line);position:relative;cursor:pointer;margin:0;transition:background .15s}
.switch input::after{content:"";position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:#fff;transition:transform .15s;box-shadow:0 1px 2px rgba(0,0,0,.2)}
.switch input:checked{background:var(--ok)}.switch input:checked::after{transform:translateX(12px)}

.view{padding:28px 36px 64px;max-width:1320px}
.view[hidden]{display:none}
.vhead{display:flex;align-items:flex-end;gap:14px;flex-wrap:wrap;margin-bottom:18px}
.vhead h1{font-size:22px;line-height:1.2;margin:0;font-weight:650;letter-spacing:-.015em}
.vhead p{margin:4px 0 0;color:var(--ink-3)}
.vhead .tools{margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.sheet{background:var(--surface);border:1px solid var(--line);border-radius:12px}
.sheet+.sheet,.gap{margin-top:18px}
.shead{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--line-2)}
.shead h2{margin:0;font-size:14px;font-weight:600}
.shead .tools{margin-left:auto;display:flex;gap:8px;align-items:center}
.sbody{padding:16px 18px}
.split{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:18px;margin-top:18px}
.split>.sheet{margin:0}

/* status */
.led{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--idle);flex:none}
.led.ok{background:var(--ok);box-shadow:0 0 0 3px var(--ok-soft)}
.led.warn{background:var(--warn);box-shadow:0 0 0 3px var(--warn-soft)}
.led.fail{background:var(--fail);box-shadow:0 0 0 3px var(--fail-soft)}
.tag{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;background:var(--sunken);color:var(--ink-2);white-space:nowrap}
.tag.ok{background:var(--ok-soft);color:var(--ok)}.tag.warn{background:var(--warn-soft);color:var(--warn)}.tag.fail{background:var(--fail-soft);color:var(--fail)}
.chip{display:inline-flex;font-size:11.5px;padding:1px 7px;border-radius:5px;border:1px solid var(--line);color:var(--ink-2);margin-left:6px;white-space:nowrap;font-weight:500}

/* diagnosis */
.verdict{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:26px 28px 24px;box-shadow:var(--shadow)}
.vstate{display:flex;align-items:center;gap:9px;font-size:13px;font-weight:600;color:var(--ink-2)}
.verdict h1{font-size:30px;line-height:1.18;letter-spacing:-.02em;font-weight:680;margin:10px 0 8px;max-width:28ch}
.verdict .lede{color:var(--ink-2);max-width:72ch;margin:0}
.verdict.fail .vstate{color:var(--fail)}.verdict.warn .vstate{color:var(--warn)}.verdict.ok .vstate{color:var(--ok)}
.when{color:var(--ink-3);font-size:12.5px;margin-top:14px}

.chain{list-style:none;margin:26px 0 4px;padding:0;display:grid;grid-template-columns:repeat(7,minmax(0,1fr))}
.stage{position:relative;display:flex;flex-direction:column;align-items:center;text-align:center;gap:2px}
.stage .wire{position:absolute;top:22px;right:50%;width:100%;height:3px;background:var(--line-2);border-radius:2px;z-index:0}
.stage:first-child .wire{display:none}
.stage .wire::after{content:"";position:absolute;inset:0;border-radius:2px;background:var(--idle);transform-origin:left;transform:scaleX(var(--fill,0));transition:transform .35s ease-out;transition-delay:calc(var(--i)*110ms)}
.chain.lit .wire::after{--fill:1}
.stage.ok .wire::after{background:var(--ok)}.stage.warn .wire::after{background:var(--warn)}
.stage.fail .wire::after{background:repeating-linear-gradient(90deg,var(--fail) 0 7px,transparent 7px 12px)}
.node{position:relative;z-index:1;width:46px;height:46px;border-radius:50%;display:grid;place-items:center;border:2px solid var(--idle);background:var(--surface);color:var(--ink-2);cursor:pointer;transition:border-color .2s,color .2s}
.node .i{width:20px;height:20px}
.stage.ok .node{border-color:var(--ok);color:var(--ok)}
.stage.warn .node{border-color:var(--warn);color:var(--warn)}
.stage.fail .node{border-color:var(--fail);color:var(--fail);background:var(--fail-soft)}
.stage.fault .node{box-shadow:0 0 0 6px var(--fail-soft)}
.stage .sname{font-weight:600;font-size:13px;margin-top:8px}
.stage .sstate{font-size:12px;color:var(--ink-3)}
.stage.fail .sstate{color:var(--fail)}.stage.warn .sstate{color:var(--warn)}
.stage.origin .node{border-color:var(--ink);color:var(--ink)}

.facts{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:0;margin-top:18px;background:var(--surface);border:1px solid var(--line);border-radius:12px}
.fact{padding:14px 16px;border-left:1px solid var(--line-2);min-width:0}
.fact:first-child{border-left:0}
.fact dt{font-size:12.5px;color:var(--ink-3)}
.fact dd{margin:3px 0 0;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fact dd.mono{font-size:13.5px}

.cols{display:grid;grid-template-columns:1fr 1fr;gap:28px;margin-top:22px;padding-top:20px;border-top:1px solid var(--line-2)}
.cols h3{font-size:13px;margin:0 0 10px;font-weight:600;color:var(--ink-2)}
.ruled{list-style:none;margin:0;padding:0;display:grid;gap:6px}
.ruled li{display:flex;gap:9px;align-items:flex-start;color:var(--ink-2)}
.ruled .i{width:16px;height:16px;color:var(--ok);margin-top:2px}
.steps{margin:0;padding-left:20px;display:grid;gap:6px;color:var(--ink)}
.steps li::marker{color:var(--ink-3);font-weight:600}

.group{padding:6px 0}
.group+.group{border-top:1px solid var(--line-2)}
.ghead{display:flex;align-items:center;gap:10px;padding:10px 18px 4px;font-weight:600;font-size:13px;color:var(--ink-2)}
.ghead .i{width:16px;height:16px}
.check{display:grid;grid-template-columns:18px minmax(140px,190px) minmax(0,1fr);gap:4px 12px;padding:8px 18px;align-items:baseline}
.check .led{transform:translateY(-1px)}
.check .cname{font-weight:550}
.check .cdet{color:var(--ink)}
.check .cfix{grid-column:3;color:var(--ink-2);font-size:13px;display:flex;gap:6px}
.check .cfix b{font-weight:600;color:var(--ink)}
.check .crule{grid-column:3;color:var(--ink-3);font-size:12.5px}
.group.flash{animation:flash 1.2s ease-out}
@keyframes flash{0%{background:var(--warn-soft)}100%{background:transparent}}

/* tables */
.tablewrap{overflow:auto;max-height:560px}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-weight:500;font-size:12.5px;color:var(--ink-3);padding:9px 14px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--surface);white-space:nowrap}
td{padding:9px 14px;border-bottom:1px solid var(--line-2);vertical-align:middle}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:var(--hover)}
tr.click{cursor:pointer}
.dev{display:flex;align-items:center;gap:11px;min-width:0}
.devicon{width:32px;height:32px;border-radius:8px;background:var(--sunken);display:grid;place-items:center;color:var(--ink-2);flex:none}
.devname{font-weight:600}
.devsub{font-size:12px;color:var(--ink-3)}
.empty{padding:28px 18px;color:var(--ink-3);text-align:center}
.loading{padding:22px 18px;color:var(--ink-3)}
.loading::before{content:"";display:inline-block;width:12px;height:12px;border:2px solid var(--line);border-top-color:var(--ink-2);border-radius:50%;margin-right:9px;vertical-align:-2px;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.note{display:flex;gap:10px;padding:11px 14px;border-radius:10px;background:var(--warn-soft);color:var(--ink);font-size:13.5px;margin:14px 18px}
.note .i{color:var(--warn);margin-top:1px}
.note.fail{background:var(--fail-soft)}.note.fail .i{color:var(--fail)}
.note.info{background:var(--sunken)}.note.info .i{color:var(--ink-2)}
.lossbar{display:flex;align-items:center;gap:8px;min-width:120px}
.lossbar span{flex:1;height:6px;border-radius:3px;background:var(--line-2);overflow:hidden}
.lossbar span i{display:block;height:100%;background:var(--ok)}
.lossbar.warn span i{background:var(--warn)}.lossbar.fail span i{background:var(--fail)}

/* topology */
.topo{display:block;width:100%;height:auto}
.topo .wire{stroke:var(--line);stroke-width:2}
.topo .bus{stroke:var(--line);stroke-width:2}
.topo .n{fill:var(--surface);stroke-width:2}
.topo .ico{color:var(--ink-2)}
.topo text{fill:var(--ink);font:600 12px var(--sans)}
.topo text.s{fill:var(--ink-3);font:400 11px var(--mono)}
.topo text.m{fill:var(--ink-3);font:400 13px var(--sans)}
.topo g[data-host]{cursor:pointer}
.topo g[data-host]:hover .n{fill:var(--hover)}

/* traffic */
.meters{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-top:1px solid var(--line-2)}
.meter{padding:14px 18px;border-left:1px solid var(--line-2)}
.meter:first-child{border-left:0}
.meter dt{font-size:12.5px;color:var(--ink-3);display:flex;align-items:center;gap:7px}
.meter dd{margin:2px 0 0;font-size:22px;font-weight:650;letter-spacing:-.01em}
.sw{width:10px;height:3px;border-radius:2px;display:inline-block}
canvas{display:block;width:100%}

/* console */
.crow{display:flex;gap:8px;flex-wrap:wrap}
.crow input{flex:1;min-width:220px;font-family:var(--mono);font-size:13px}
.presets{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
.presets button{border:1px solid var(--line);background:var(--sunken);border-radius:6px;padding:4px 9px;font:12px var(--mono);cursor:pointer;color:var(--ink-2)}
.presets button:hover{color:var(--ink);border-color:var(--ink-3)}
.term{background:#0D1319;color:#D7E0E8;border-radius:10px;padding:14px 16px;white-space:pre-wrap;word-break:break-word;min-height:260px;max-height:62vh;overflow:auto;margin:14px 0 0;font:12.5px/1.55 var(--mono)}
.term .p{color:#7FB2FF}
.toolgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:0}
.tool{display:flex;gap:10px;align-items:flex-start;padding:8px 18px}
.tool .i{width:16px;height:16px;margin-top:2px}
.tool.on .i{color:var(--ok)}.tool.off{color:var(--ink-3)}.tool.off .i{color:var(--ink-3)}
.tool b{font-family:var(--mono);font-weight:600;font-size:13px}
.tool div div{font-size:12.5px;color:var(--ink-3)}
pre.plain{margin:0;font:12px/1.5 var(--mono);white-space:pre-wrap;color:var(--ink-2)}
.copy{display:flex;gap:8px;align-items:center;background:var(--sunken);border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin-top:8px}
.copy code{flex:1;font:12.5px var(--mono);overflow-x:auto;white-space:nowrap}

/* drawer */
.scrim{position:fixed;inset:0;background:rgba(10,16,22,.42);z-index:40;display:flex;justify-content:flex-end}
.scrim[hidden]{display:none}
.drawer{width:min(520px,100%);height:100%;background:var(--surface);border-left:1px solid var(--line);overflow:auto;padding:22px 24px;animation:slide .2s ease-out}
@keyframes slide{from{transform:translateX(24px);opacity:.4}}
.drawer h2{margin:0;font-size:20px;letter-spacing:-.01em}
.dl{display:grid;grid-template-columns:max-content 1fr;gap:8px 18px;margin:18px 0;font-size:13.5px}
.dl dt{color:var(--ink-3)}.dl dd{margin:0;min-width:0;overflow-wrap:anywhere}
.drawer .term{min-height:180px}
.dtop{display:flex;align-items:flex-start;gap:14px}
.dtop .devicon{width:44px;height:44px;border-radius:11px}
.dtop .devicon .i{width:22px;height:22px}
.dtop .x{margin-left:auto}

@media (max-width:1100px){.facts{grid-template-columns:repeat(3,minmax(0,1fr))}.fact:nth-child(4){border-left:0}.fact:nth-child(n+4){border-top:1px solid var(--line-2)}.split{grid-template-columns:1fr}}
@media (max-width:860px){
 .app{grid-template-columns:1fr;background:none}
 .shead .muted{display:none}
 .side{position:sticky;top:0;z-index:20;height:auto;flex-direction:row;align-items:center;padding:8px 12px;border-right:0;border-bottom:1px solid var(--line);overflow-x:auto;gap:4px}
 .brand{padding:0 10px 0 4px}.brand span{display:none}
 .nav{flex-direction:row}.nav button{width:auto;white-space:nowrap}.nav .count,.nav .led{display:none}
 .side-foot{display:none}
 .bar{position:static;padding:12px 16px;flex-wrap:wrap}
 .view{padding:20px 16px 48px}
 .verdict{padding:20px}.verdict h1{font-size:24px}
 .chain{grid-template-columns:1fr;gap:0}
 .stage{flex-direction:row;text-align:left;gap:12px;padding:6px 0;flex-wrap:wrap}
 .stage .wire{display:none}.stage .sname{margin:0}
 .facts{grid-template-columns:repeat(2,minmax(0,1fr))}.fact{border-left:0!important;border-top:1px solid var(--line-2)}
 .fact:nth-child(-n+2){border-top:0}
 .cols{grid-template-columns:1fr}
 .check{grid-template-columns:18px minmax(0,1fr)}.check .cdet,.check .cfix,.check .crule{grid-column:2}
 .meters{grid-template-columns:1fr}.meter{border-left:0;border-top:1px solid var(--line-2)}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style></head><body>

<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<symbol id="i-diag" viewBox="0 0 24 24"><path d="M3 12h4l2.5-6 5 12 2.5-6h4"/></symbol>
<symbol id="i-computer" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></symbol>
<symbol id="i-devices" viewBox="0 0 24 24"><rect x="2.5" y="5" width="13" height="9" rx="1.5"/><path d="M6 18h6M9 14v4"/><rect x="17" y="8" width="4.5" height="10" rx="1.2"/></symbol>
<symbol id="i-path" viewBox="0 0 24 24"><circle cx="6" cy="18" r="2.2"/><circle cx="18" cy="6" r="2.2"/><path d="M8.2 18H14a3 3 0 0 0 0-6h-4a3 3 0 0 1 0-6h5.8"/></symbol>
<symbol id="i-traffic" viewBox="0 0 24 24"><path d="M7 4v16M7 4 4 7M7 4l3 3M17 20V4M17 20l-3-3M17 20l3-3"/></symbol>
<symbol id="i-plug" viewBox="0 0 24 24"><path d="M9 3v4M15 3v4M6.5 7h11v4a5.5 5.5 0 0 1-11 0zM12 16.5V21"/></symbol>
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
</defs></svg>

<div class="app">
 <aside class="side">
  <div class="brand">
   <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="1.5" y="1.5" width="21" height="21" rx="5.5" fill="var(--ink)"/><rect x="5" y="5" width="6" height="6" rx="1.6" fill="var(--ok)"/><rect x="13" y="5" width="6" height="6" rx="1.6" fill="var(--surface)" opacity=".35"/><rect x="5" y="13" width="6" height="6" rx="1.6" fill="var(--surface)" opacity=".35"/><rect x="13" y="13" width="6" height="6" rx="1.6" fill="var(--surface)" opacity=".35"/></svg>
   <span>NetPane</span>
  </div>
  <nav class="nav" aria-label="Sections">
   <button data-go="diagnosis"><svg class="i"><use href="#i-diag"/></svg>Diagnosis<span class="led" id="navled"></span></button>
   <button data-go="devices"><svg class="i"><use href="#i-devices"/></svg>Devices<span class="count" id="navdev"></span></button>
   <button data-go="path"><svg class="i"><use href="#i-path"/></svg>Path</button>
   <button data-go="traffic"><svg class="i"><use href="#i-traffic"/></svg>Traffic</button>
   <button data-go="connections"><svg class="i"><use href="#i-plug"/></svg>Connections</button>
   <button data-go="interfaces"><svg class="i"><use href="#i-port"/></svg>Interfaces</button>
   <button data-go="tools"><svg class="i"><use href="#i-console"/></svg>Tools</button>
  </nav>
  <div class="side-foot">
   <div class="host" id="hostinfo">Connecting…</div>
   <button class="iconbtn" id="theme"><svg class="i"><use href="#i-moon"/></svg><span>Dark mode</span></button>
  </div>
 </aside>

 <main>
  <div class="bar">
   <div><div class="title" id="bartitle">Diagnosis</div></div>
   <div class="grow"></div>
   <label class="switch"><input type="checkbox" id="auto"> Recheck every minute</label>
   <a class="btn" href="/api/report.txt" title="Plain-text report for a ticket or email"><svg class="i"><use href="#i-download"/></svg>Report</a>
   <button class="btn primary" id="runall"><svg class="i"><use href="#i-refresh"/></svg><span>Run checks</span></button>
  </div>

  <!-- DIAGNOSIS -->
  <section class="view" id="v-diagnosis">
   <div class="verdict" id="verdict">
    <div class="vstate"><span class="led"></span>Checking</div>
    <h1>Looking at your network…</h1>
    <p class="lede">Testing each link from this computer out to the web. This takes about 15 seconds.</p>
    <ol class="chain" id="chain"></ol>
    <div id="vcols"></div>
   </div>
   <dl class="facts" id="facts"></dl>
   <div class="sheet gap">
    <div class="shead"><h2>Every check</h2><span class="muted" style="font-size:13px">In the order traffic travels. The first failure is the fault; everything that passed before it is ruled out.</span></div>
    <div id="checks"><div class="loading">Running checks</div></div>
   </div>
  </section>

  <!-- DEVICES -->
  <section class="view" id="v-devices" hidden>
   <div class="vhead"><div><h1>Devices</h1><p id="nmeta">Everything that answered on your local network.</p></div>
    <div class="tools"><input class="field" id="nfilter" placeholder="Filter by name, IP, MAC or maker" style="width:260px"><button class="btn" id="rescan"><svg class="i"><use href="#i-search"/></svg>Scan again</button></div></div>
   <div class="sheet"><div class="sbody" id="topo"></div></div>
   <div class="sheet"><div id="neigh"><div class="loading">Scanning the subnet and looking up names</div></div></div>
  </section>

  <!-- PATH -->
  <section class="view" id="v-path" hidden>
   <div class="vhead"><div><h1>Path</h1><p>Every router between you and a destination, and where delay or loss starts.</p></div>
    <form class="tools" id="pathf"><input class="field" id="ptarget" value="1.1.1.1" aria-label="Destination" style="width:220px"><button class="btn primary">Trace</button></form></div>
   <div class="sheet"><div id="path"><div class="loading">Tracing</div></div></div>
  </section>

  <!-- TRAFFIC -->
  <section class="view" id="v-traffic" hidden>
   <div class="vhead"><div><h1>Traffic</h1><p>Live throughput, sampled every second for the last two minutes.</p></div>
    <div class="tools"><select class="field" id="tiface" aria-label="Interface"></select></div></div>
   <div class="sheet"><div class="sbody"><canvas id="tchart" height="300"></canvas></div><dl class="meters" id="tnow"></dl></div>
   <div class="sheet" id="vnstatbox" hidden><div class="shead"><h2>History</h2><span class="muted" style="font-size:13px">from vnstat</span></div><div class="sbody"><pre class="plain" id="vnstat"></pre></div></div>
  </section>

  <!-- CONNECTIONS -->
  <section class="view" id="v-connections" hidden>
   <div class="vhead"><div><h1>Connections</h1><p>What this computer is listening on, and who it is talking to.</p></div>
    <div class="tools"><button class="btn" id="resock"><svg class="i"><use href="#i-refresh"/></svg>Refresh</button></div></div>
   <div class="split">
    <div class="sheet"><div class="shead"><h2>Listening ports</h2></div><div id="listen"><div class="loading">Reading sockets</div></div></div>
    <div class="sheet"><div class="shead"><h2>Open connections</h2></div><div id="estab"></div></div>
   </div>
  </section>

  <!-- INTERFACES -->
  <section class="view" id="v-interfaces" hidden>
   <div class="vhead"><div><h1>Interfaces</h1><p>Network adapters, addresses, routing and DNS on this computer.</p></div></div>
   <div class="sheet"><div id="ifaces"><div class="loading">Reading interfaces</div></div></div>
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
  <section class="view" id="v-tools" hidden>
   <div class="vhead"><div><h1>Tools</h1><p>Run any of the underlying tools directly. Safe limits are added for you, so nothing runs forever.</p></div></div>
   <div class="sheet"><div class="sbody">
    <div class="crow"><select class="field" id="ctool" aria-label="Tool"></select><input class="field" id="cargs" placeholder="Arguments" aria-label="Arguments"><button class="btn primary" id="crun"><svg class="i"><use href="#i-play"/></svg>Run</button><button class="btn" id="cclear">Clear</button></div>
    <div class="presets" id="cpresets"></div>
    <pre class="term" id="cout">Choose a tool, then press Run or pick one of the examples.</pre>
   </div></div>
   <div class="sheet"><div class="shead"><h2>Installed tools</h2><span class="muted" id="tcount" style="font-size:13px"></span></div><div id="tools"></div></div>
  </section>
 </main>
</div>

<div class="scrim" id="scrim" hidden><aside class="drawer" role="dialog" aria-modal="true" id="drawer"></aside></div>

<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const ic=(n,c="i")=>`<svg class="${c}"><use href="#i-${n}"/></svg>`;
const S={tif:null,view:"diagnosis"};
const WORD={pass:"Passed",warn:"Warning",fail:"Failed",skip:"Not run"};
const CLS={pass:"ok",warn:"warn",fail:"fail",skip:""};
const tag=s=>`<span class="tag ${CLS[s]||""}">${WORD[s]||esc(s)}</span>`;
const short=(s,n)=>{s=String(s??"");return s.length>n?s.slice(0,n-1)+"…":s};
function bytes(n){if(n==null)return "";const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1024&&i<4){n/=1024;i++}return n.toFixed(i?1:0)+" "+u[i]}
function rate(Bps){let b=Bps*8;const u=["bps","Kbps","Mbps","Gbps"];let i=0;while(b>=1000&&i<3){b/=1000;i++}return b.toFixed(i&&b<100?1:0)+" "+u[i]}
function tbl(cols,rows,empty){if(!rows||!rows.length)return `<div class="empty">${empty||"Nothing to show."}</div>`;
 return `<div class="tablewrap"><table><thead><tr>${cols.map(c=>`<th>${c[0]}</th>`).join("")}</tr></thead><tbody>${rows.map(r=>`<tr${c0(r)}>${cols.map(c=>`<td>${c[1](r)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`}
let c0=()=>"";
function count(a,f){const m={};a.forEach(x=>{const k=f(x);m[k]=(m[k]||0)+1});return Object.entries(m).sort((a,b)=>b[1]-a[1])}
async function api(p,o){const r=await fetch(p,o);let j;try{j=await r.json()}catch(e){throw new Error("NetPane returned an unreadable response ("+r.status+").")}if(!r.ok||(j.error&&!j.hosts&&!j.hops))throw new Error(j.error||("Request failed with "+r.status));return j}
const loading=(id,msg)=>$(id).innerHTML=`<div class="loading">${msg||"Loading"}</div>`;
const fail=(id,e)=>$(id).innerHTML=`<div class="note fail">${ic("alert")}<div>${esc(e.message||e)}</div></div>`;
const KICON={computer:"computer",router:"router",phone:"phone",printer:"printer",server:"server",camera:"camera",unknown:"unknown"};

/* ---------- navigation & theme ---------- */
const TITLES={diagnosis:"Diagnosis",devices:"Devices",path:"Path",traffic:"Traffic",connections:"Connections",interfaces:"Interfaces",tools:"Tools"};
function go(v){if(!TITLES[v])v="diagnosis";S.view=v;
 document.querySelectorAll(".view").forEach(x=>x.hidden=x.id!=="v-"+v);
 document.querySelectorAll("[data-go]").forEach(b=>b.dataset.go===v?b.setAttribute("aria-current","page"):b.removeAttribute("aria-current"));
 $("#bartitle").textContent=TITLES[v];if(location.hash.slice(1)!==v)history.replaceState(null,"","#"+v);
 if(v==="traffic")drawChart();if(v==="tools")showPresets();window.scrollTo(0,0)}
function setTheme(t){const r=document.documentElement;if(t)r.dataset.theme=t;else delete r.dataset.theme;
 try{t?localStorage.setItem("np-theme",t):localStorage.removeItem("np-theme")}catch(e){}
 const dark=isDark();$("#theme").innerHTML=ic(dark?"sun":"moon")+`<span>${dark?"Light":"Dark"} mode</span>`;drawChart();if(S.ov)drawTopo()}
const isDark=()=>{const t=document.documentElement.dataset.theme;return t?t==="dark":matchMedia("(prefers-color-scheme: dark)").matches};
$("#theme").onclick=()=>setTheme(isDark()?"light":"dark");
try{const t=localStorage.getItem("np-theme");if(t)document.documentElement.dataset.theme=t}catch(e){}

/* ---------- overview ---------- */
async function loadOverview(){
 try{const o=await api("/api/overview");S.ov=o;
  $("#hostinfo").innerHTML=`<b>${esc(o.hostname)}</b><br>${esc(o.primary||"no network")}${o.root?"":`<br><span title="Start with sudo for arping, tcpdump, nethogs and process names">Limited mode (not root)</span>`}`;
  if(!S.tif)S.tif=o.primary;renderIfaces();renderRoutes();renderHw();renderFacts();drawTopo();
 }catch(e){fail("#ifaces",e);$("#hostinfo").textContent="Can't reach NetPane. Is it still running?"}}

function renderIfaces(){const o=S.ov;
 $("#ifaces").innerHTML=tbl([
  ["Interface",i=>`<div class="dev"><div class="devicon">${ic(i.wireless?"wifi":"port")}</div><div><div class="devname">${esc(i.name)}${i.name===o.primary?'<span class="chip">primary</span>':""}${i.virtual?'<span class="chip">virtual</span>':""}</div><div class="devsub">${esc(i.driver||(i.virtual?"software device":""))}</div></div></div>`],
  ["Status",i=>{const up=i.carrier!=="0"&&i.state!=="DOWN";return `<span class="tag ${up?(i.state==="UP"?"ok":"warn"):"fail"}">${up?"Connected":"No link"}</span>`}],
  ["Address",i=>`<div class="mono">${esc(i.ipv4.join(", ")||"none")}</div>${i.ipv6.length?`<div class="mono muted" style="font-size:11.5px">${esc(short(i.ipv6[0],30))}</div>`:""}`],
  ["Hardware address",i=>`<div class="mono">${esc(i.mac)}</div><div class="devsub">${esc(i.vendor)}</div>`],
  ["Speed",i=>i.wifi&&i.wifi.ssid?`${esc(i.wifi.ssid)}<div class="devsub">${esc(i.wifi.signal??"?")} dBm, ${esc(i.wifi.bitrate||"")}</div>`:(i.speed?`${i.speed>=1000?i.speed/1000+" Gb/s":i.speed+" Mb/s"}<div class="devsub">${esc(i.duplex||"")} duplex</div>`:'<span class="muted">n/a</span>')],
  ["MTU",i=>esc(i.mtu)],
  ["Received / sent",i=>`${bytes(i.rx_bytes)}<div class="devsub">${bytes(i.tx_bytes)} sent</div>`],
  ["Errors",i=>{const e=(i.rx_errors||0)+(i.tx_errors||0),d=(i.rx_dropped||0)+(i.tx_dropped||0);return `${e?`<span class="tag fail">${e} errors</span>`:"None"}${d?`<div class="devsub">${d} dropped</div>`:""}`}]
 ],o.interfaces.filter(i=>!i.loopback),"No network adapters found.")}
function renderRoutes(){const o=S.ov;if(!o)return;const d=o.dns;
 $("#routes").innerHTML=tbl([["Destination",r=>`<span class="mono">${esc(r.dst==="default"?"Everything else (default)":r.dst)}</span>`],["Via",r=>`<span class="mono">${esc(r.gateway||"Direct")}</span>`],["Interface",r=>esc(r.dev||"")],["Metric",r=>esc(r.metric??"")]],o.routes.ipv4,"No routes. This computer can't reach any network.");
 $("#dns").innerHTML=`<dl class="dl" style="margin:0"><dt>Servers</dt><dd class="mono">${esc(d.resolv_conf.join(", ")||"None configured")}${d.stub?' <span class="chip">local cache</span>':""}</dd>
  ${d.upstream.length?`<dt>Forwards to</dt><dd class="mono">${esc(d.upstream.join(", "))}</dd>`:""}
  ${d.search.length?`<dt>Search domains</dt><dd>${esc(d.search.join(", "))}</dd>`:""}
  <dt>Public IP</dt><dd class="mono">${esc(S.health?(S.health.public_ip||"Unknown"):"Checking")}</dd></dl>`}
function renderHw(){const o=S.ov,e=o.extras||{};
 let x=`<dl class="dl" style="margin:0 0 12px"><dt>Hostname</dt><dd>${esc(o.fqdn)}</dd><dt>Kernel</dt><dd>${esc(o.kernel)}</dd><dt>Running as</dt><dd>${o.root?"root, full access":esc(o.user||"user")+", limited. Start with sudo for everything."}</dd></dl>`;
 if(e.pci&&e.pci.length)x+=`<pre class="plain">${esc(e.pci.join("\n"))}</pre>`;
 if(e.nmcli&&e.nmcli.length)x+=`<div style="margin-top:12px">`+tbl([["Device",r=>esc(r[0])],["Type",r=>esc(r[1])],["State",r=>esc(r[2])],["Connection",r=>esc(r[3]||"")]],e.nmcli)+`</div>`;
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
 $("#verdict").innerHTML=`<div class="vstate"><span class="led"></span>Checking</div><h1>Looking at your network…</h1><p class="lede">Testing each link from this computer out to the web. This takes about 15 seconds.</p><ol class="chain" id="chain">${chainHTML(null)}</ol>`}
async function loadHealth(){renderVerdictWaiting();loading("#checks","Running checks");$("#navled").className="led";
 try{S.health=await api("/api/health");renderHealth();renderRoutes();renderFacts();drawTopo()}catch(e){fail("#checks",e)}}
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
   <div><h3>${steps.length?"What to do next":"If something still fails"}</h3>${steps.length?`<ol class="steps">${steps.map(s=>`<li>${esc(s)}</li>`).join("")}</ol>`:`<p class="soft" style="margin:0">Trace the path to the specific server in the Path tab, or check the application and this computer's firewall.</p>`}</div></div>`:""}
  <div class="when">Checked at ${esc(h.time.split(" ")[1])} on ${esc(h.interface||"?")}</div>`;
 requestAnimationFrame(()=>requestAnimationFrame(()=>$("#chain")&&$("#chain").classList.add("lit")));
 $("#checks").innerHTML=STAGES.map(st=>{const cs=h.checks.filter(c=>st.checks.includes(c.name));if(!cs.length)return "";
  return `<div class="group" id="g-${st.k}"><div class="ghead">${ic(st.icon)}${st.name}</div>${cs.map(c=>`<div class="check"><span class="led ${CLS[c.status]}" title="${WORD[c.status]}"></span><span class="cname">${esc(c.name)}</span><span class="cdet">${esc(c.detail)}</span>${c.status!=="pass"&&c.fix?`<span class="cfix"><b>Fix</b>${esc(c.fix)}</span>`:""}${c.status==="pass"?`<span class="crule">Rules out ${esc(/^[A-Z][a-z]/.test(c.rules_out)?c.rules_out.charAt(0).toLowerCase()+c.rules_out.slice(1):c.rules_out)}</span>`:""}</div>`).join("")}</div>`}).join("")}
function renderFacts(){const o=S.ov,h=S.health,n=S.neigh;if(!o)return;
 const me=(o.interfaces||[]).find(i=>i.name===o.primary);
 const q=h&&h.checks.find(c=>c.name==="Line quality");const m=q&&q.detail.match(/([\d.]+) ms average/);
 const link=me?(me.wifi&&me.wifi.ssid?`${me.wifi.ssid}, ${me.wifi.signal} dBm`:(me.speed?(me.speed>=1000?me.speed/1000+" Gb/s":me.speed+" Mb/s")+" wired":me.name)):"None";
 const F=[["This computer",me?.ipv4?.[0]?.split("/")[0]||"No address",1],["Gateway",o.gateway?.gateway||"None",1],["Public IP",h?(h.public_ip||"Unknown"):"Checking",1],
  ["Connection",link,0],["Latency",m?Math.round(+m[1])+" ms":(h?"n/a":"Checking"),0],["Devices nearby",n?(n.error?"n/a":String(n.count)):"Scanning",0]];
 $("#facts").innerHTML=F.map(f=>`<div class="fact"><dt>${f[0]}</dt><dd class="${f[2]?"mono":""}" title="${esc(f[1])}">${esc(f[1])}</dd></div>`).join("")}

/* ---------- devices ---------- */
async function loadNeighbors(){loading("#neigh","Scanning the subnet and looking up names. This can take up to a minute.");$("#nmeta").textContent="Scanning…";$("#navdev").textContent="";
 try{S.neigh=await api("/api/neighbors");renderNeigh();drawTopo();renderFacts()}catch(e){fail("#neigh",e)}}
function renderNeigh(){const n=S.neigh;if(!n)return;
 if(n.error){$("#neigh").innerHTML=`<div class="note">${ic("alert")}<div>${esc(n.error)}</div></div>`;$("#nmeta").textContent="Couldn't scan.";return}
 $("#nmeta").textContent=`${n.count} ${n.count===1?"device":"devices"} on ${n.network}, found with ${n.method}.`;$("#navdev").textContent=n.count;
 const f=$("#nfilter").value.toLowerCase();
 const rows=n.hosts.filter(h=>!f||[h.name,h.ip,h.mac,h.vendor,h.role].join(" ").toLowerCase().includes(f));
 c0=h=>` class="click" data-host="${esc(h.ip)}" tabindex="0"`;
 $("#neigh").innerHTML=tbl([
  ["Device",h=>`<div class="dev"><div class="devicon">${ic(KICON[h.kind]||"unknown")}</div><div><div class="devname">${esc(h.name||"Unnamed device")}${h.role?`<span class="chip">${esc(h.role)}</span>`:""}</div><div class="devsub">${esc(h.name_source?("Name from "+h.name_source):"No name published")}</div></div></div>`],
  ["IP address",h=>`<span class="mono">${esc(h.ip)}</span>`],["Hardware address",h=>`<span class="mono">${esc(h.mac||"Unknown")}</span>`],
  ["Maker",h=>esc(h.vendor||"Unknown")],
  ["Status",h=>`<span class="tag ${h.alive?"ok":"warn"}">${h.alive?"Online":"Seen recently"}</span>`]],rows,f?"No devices match that filter.":"No other devices answered.");c0=()=>""}
function showHost(ip){const h=(S.neigh?.hosts||[]).find(x=>x.ip===ip)||{ip,name:ip===S.ov?.gateway?.gateway?"Gateway":"",kind:"router"};
 const kind=KICON[h.kind]||"unknown";
 $("#drawer").innerHTML=`<div class="dtop"><div class="devicon">${ic(kind)}</div><div><h2>${esc(h.name||"Unnamed device")}</h2><div class="muted mono">${esc(ip)}</div></div><button class="btn sm x" id="dclose" aria-label="Close">${ic("x")}</button></div>
  <dl class="dl"><dt>Hardware address</dt><dd class="mono">${esc(h.mac||"Unknown")}</dd><dt>Maker</dt><dd>${esc(h.vendor||"Unknown")}</dd>
  <dt>Name from</dt><dd>${esc(h.name_source||"Not published")}</dd><dt>Role</dt><dd>${esc(h.role||"Device on this network")}</dd><dt>Neighbour state</dt><dd>${esc(h.state||"")}</dd><dt>Likely type</dt><dd id="dguess">Scan its ports to find out</dd></dl>
  <div class="crow"><button class="btn" data-act="ping">Ping</button><button class="btn primary" data-act="scan">Scan ports</button><button class="btn" data-act="trace">Trace path</button></div>
  <pre class="term" id="hout">Results appear here.</pre>`;
 $("#scrim").hidden=false;$("#dclose").focus();$("#dclose").onclick=closeDrawer;
 $("#drawer").querySelectorAll("[data-act]").forEach(b=>b.onclick=async()=>{const out=$("#hout");out.textContent="Running…";b.disabled=true;
  try{if(b.dataset.act==="scan"){const r=await api("/api/scanhost?ip="+encodeURIComponent(ip));$("#dguess").textContent=r.guess;
     out.textContent=`${r.method}\n\n`+(r.ports.length?"PORT    PROTO  SERVICE\n"+r.ports.map(p=>`${String(p.port).padEnd(8)}${p.proto.padEnd(7)}${p.service}`).join("\n"):"No open ports found.")}
   else if(b.dataset.act==="ping")out.textContent=await runTool("ping",`-c 4 ${ip}`);
   else{const mtr=(S.tools||[]).find(t=>t.cmd==="mtr"&&t.installed);out.textContent=await runTool(mtr?"mtr":"traceroute",`-n ${ip}`)}
  }catch(e){out.textContent=e.message}b.disabled=false})}
function closeDrawer(){$("#scrim").hidden=true}
$("#scrim").onclick=e=>{if(e.target.id==="scrim")closeDrawer()};
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeDrawer();if(e.key==="Enter"&&e.target.matches("tr[data-host]"))showHost(e.target.dataset.host)});

/* ---------- topology ---------- */
function drawTopo(){const o=S.ov,h=S.health,n=S.neigh;if(!o)return;
 const st=nm=>(h?.checks||[]).find(c=>c.name===nm)?.status||"skip";
 const w=(...a)=>a.includes("fail")?"fail":a.includes("warn")?"warn":a.every(x=>x==="skip")?"skip":"pass";
 const col=s=>({pass:"var(--ok)",warn:"var(--warn)",fail:"var(--fail)",skip:"var(--idle)"}[s]);
 const sLan=w(st("Physical link"),st("Gateway ARP")),sGw=w(st("Gateway ARP"),st("Gateway ping")),sWan=w(st("Internet by IP"),st("TCP egress"),st("DNS servers"),st("HTTPS"));
 const gw=o.gateway?.gateway,me=(o.interfaces||[]).find(i=>i.name===o.primary);
 const others=(n?.hosts||[]).filter(x=>x.role!=="This host"&&x.role!=="Gateway");
 const per=7,rows=Math.max(1,Math.ceil(others.length/per)),W=1000,busY=150,H=others.length?busY+36+rows*92:busY+80;
 const big=(x,y,icon,label,sub,s,ip)=>`<g${ip?` data-host="${esc(ip)}"`:""}><circle class="n" cx="${x}" cy="${y}" r="28" stroke="${col(s)}"/><svg class="ico" x="${x-12}" y="${y-12}" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><use href="#i-${icon}"/></svg><text x="${x}" y="${y+48}" text-anchor="middle">${esc(label)}</text><text class="s" x="${x}" y="${y+63}" text-anchor="middle">${esc(sub)}</text></g>`;
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
  g+=`<g data-host="${esc(x.ip)}"><title>${esc((x.name||"Unnamed")+"  "+x.ip+"  "+(x.vendor||""))}</title><circle class="n" cx="${cx}" cy="${cy}" r="19" stroke="${x.alive?"var(--ok)":"var(--warn)"}"/><svg class="ico" x="${cx-9}" y="${cy-9}" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><use href="#i-${KICON[x.kind]||"unknown"}"/></svg><text x="${cx}" y="${cy+36}" text-anchor="middle" style="font-size:11.5px">${esc(short(x.name||x.vendor||"Unnamed",18))}</text><text class="s" x="${cx}" y="${cy+50}" text-anchor="middle">${esc(x.ip)}</text></g>`});
 g+=big(140,52,"computer","This computer",me?.ipv4?.[0]?.split("/")[0]||"",w(st("Physical link"),st("IP address")),null)+big(500,52,"router","Gateway",gw||"none",gw?sGw:"fail",gw)+big(860,52,"globe","Internet",h?.public_ip||"",sWan,null);
 $("#topo").innerHTML=g+"</svg>"}

/* ---------- path ---------- */
async function loadPath(t){t=t||$("#ptarget").value.trim()||"1.1.1.1";loading("#path",`Tracing the route to ${esc(t)}. This takes up to a minute.`);
 try{S.path=await api("/api/path?target="+encodeURIComponent(t));renderPath();drawTopo()}catch(e){fail("#path",e)}}
function renderPath(){const p=S.path;if(p.error&&!p.hops.length){$("#path").innerHTML=`<div class="note fail">${ic("alert")}<div>${esc(p.error)}</div></div>`;return}
 const hops=p.hops;let bad=-1;const last=hops[hops.length-1];
 if(last&&last.loss>0){for(let i=hops.length-1;i>=0;i--){if(hops[i].loss>0)bad=i;else break}}
 const lb=l=>{const c=l==null?"":l>=100?"fail":l>0?"warn":"";return `<div class="lossbar ${c}"><span><i style="width:${l==null?0:Math.max(l,l>0?4:0)}%"></i></span>${l==null?"?":l+"%"}</div>`};
 $("#path").innerHTML=`<div class="shead"><h2>${esc(p.target)}${p.dest_ip&&p.dest_ip!==p.target?` <span class="muted mono" style="font-weight:400">${esc(p.dest_ip)}</span>`:""}</h2><div class="tools">${p.reached?'<span class="tag ok">Destination reached</span>':'<span class="tag fail">Destination not reached</span>'}<span class="muted" style="font-size:12.5px">${esc(p.method)}</span></div></div>`+
 (bad>=0?`<div class="note fail">${ic("alert")}<div>Loss starts at hop ${esc(hops[bad].hop)} (<span class="mono">${esc(hops[bad].host)}</span>) and continues to the end. That router, or the link just before it, is the likely problem.</div></div>`:"")+
 tbl([["Hop",h=>`<span class="muted">${esc(h.hop)}</span>`],["Router",h=>`<span class="mono">${esc(h.host==="???"?"No reply":h.host)}</span>${h.name?`<div class="devsub">${esc(short(h.name,48))}</div>`:""}`],
  ["Loss",h=>lb(h.loss)],["Average",h=>h.avg!=null&&h.loss<100?h.avg+" ms":"<span class='muted'>n/a</span>"],["Best",h=>h.best!=null&&h.loss<100?h.best+" ms":""],["Worst",h=>h.worst!=null&&h.loss<100?h.worst+" ms":""]],hops)+
 `<div class="note info">${ic("info")}<div>Loss on a single middle hop that doesn't continue to the end is usually that router choosing not to answer pings. It isn't a fault.</div></div>`}

/* ---------- connections ---------- */
async function loadSockets(){loading("#listen","Reading sockets");$("#estab").innerHTML="";try{S.sock=await api("/api/sockets");renderSockets()}catch(e){fail("#listen",e)}}
function renderSockets(){const s=S.sock;
 $("#listen").innerHTML=(s.note?`<div class="note info">${ic("info")}<div>${esc(s.note)}</div></div>`:"")+tbl([
  ["Port",r=>`<span class="mono">${esc(r.local.replace(/^.*:/,""))}</span> <span class="muted">${esc(r.proto)}</span>`],
  ["Bound to",r=>`<span class="mono">${esc(r.local.replace(/:[^:]*$/,""))}</span>`],
  ["Reachable from",r=>/^(127\.|\[::1\]|::1|localhost)/.test(r.local)?'<span class="muted">This computer only</span>':'<span class="tag warn">The network</span>'],
  ["Program",r=>esc(r.process||"Unknown")+(r.pid?` <span class="muted">${esc(r.pid)}</span>`:"")]],s.listening,"Nothing is listening.");
 const st=count(s.all,r=>r.state),pr=count(s.established,r=>r.process||"Unknown"),pe=count(s.established,r=>r.peer.replace(/:[^:]+$/,""));
 const NAMES={ESTAB:"Open",LISTEN:"Listening",UNCONN:"UDP open","TIME-WAIT":"Closing (time-wait)","CLOSE-WAIT":"Waiting to close","SYN-SENT":"Connecting"};
 $("#estab").innerHTML=`<div class="sbody"><dl class="dl" style="margin:0">${st.map(([k,v])=>`<dt>${esc(NAMES[k]||k)}</dt><dd>${v}</dd>`).join("")}</dl></div>
  <div class="shead" style="border-top:1px solid var(--line-2)"><h2>Busiest programs</h2></div>${tbl([["Program",r=>esc(r[0])],["Connections",r=>r[1]]],pr.slice(0,8),"No open connections.")}
  <div class="shead" style="border-top:1px solid var(--line-2)"><h2>Busiest remote addresses</h2></div>${tbl([["Address",r=>`<span class="mono">${esc(r[0])}</span>`],["Connections",r=>r[1]]],pe.slice(0,8),"None.")}`}

/* ---------- wifi ---------- */
const sigWord=d=>d>=-55?"Excellent":d>=-67?"Good":d>=-75?"Fair":"Weak";
async function loadWifi(){try{S.wifi=await api("/api/wifi");renderWifi()}catch(e){fail("#wifi",e)}}
function renderWifi(){const w=S.wifi||{networks:[]},cur=(S.ov?.interfaces||[]).filter(i=>i.wireless);
 if(!cur.length&&!w.networks.length){$("#wifi").innerHTML=`<div class="empty">This computer has no Wi-Fi adapter.</div>`;return}
 let x=cur.map(i=>`<div class="sbody"><dl class="dl" style="margin:0"><dt>${esc(i.name)}</dt><dd>${i.wifi&&i.wifi.ssid?`<b>${esc(i.wifi.ssid)}</b>, ${esc(i.wifi.signal)} dBm (${sigWord(i.wifi.signal)}), ${esc(i.wifi.freq||"?")} MHz, ${esc(i.wifi.bitrate||"")}`:'<span class="tag warn">Not connected</span>'}</dd></dl></div>`).join("");
 if(w.networks.length){const ch=count(w.networks,n=>n.chan);
  x+=tbl([["Network",n=>`${n.inuse?'<span class="led ok" style="margin-right:8px"></span>':""}${esc(n.ssid||"Hidden network")}`],["Channel",n=>esc(n.chan)],["Signal",n=>`${esc(n.signal)}%`],["Security",n=>esc(n.security)]],w.networks.slice(0,15));
  x+=`<div class="sbody muted" style="font-size:12.5px">Most crowded channels: ${ch.slice(0,4).map(c=>`${esc(c[0])} (${c[1]} networks)`).join(", ")}</div>`}
 else if(w.note)x+=`<div class="note info">${ic("info")}<div>${esc(w.note)}</div></div>`;
 $("#wifi").innerHTML=x}

/* ---------- tools & console ---------- */
const PRESETS={ping:["-c 4 {gw}","-c 4 1.1.1.1","-c 4 google.com"],traceroute:["-n 1.1.1.1"],tracepath:["-n 1.1.1.1"],mtr:["-n 1.1.1.1","-n google.com"],
 hping3:["-S -p 443 -c 3 1.1.1.1"],fping:["-a -g {net}","-c 3 {gw} 1.1.1.1 8.8.8.8"],ip:["addr","route","neigh","-s link","rule"],ifconfig:["-a"],
 ethtool:["{dev}","-i {dev}","-S {dev}"],iw:["dev","dev {dev} link"],iwconfig:[""],nmcli:["device","connection show","device wifi list","general"],
 lspci:["-nn"],lshw:["-class network -short"],route:["-n"],arp:["-n"],arping:["-c 3 -I {dev} {gw}"],ss:["-tulpn","-tunap","-s"],netstat:["-tulpn","-i","-rn"],
 lsof:["-i -P -n"],nc:["-zv -w 3 {gw} 80","-zv -w 3 google.com 443"],dig:["google.com","+trace google.com","-x 8.8.8.8","MX gmail.com"],nslookup:["google.com"],
 host:["google.com"],whois:["8.8.8.8","google.com"],tcpdump:["-i {dev} -c 30","-i {dev} -c 30 port 53","-i {dev} -c 20 arp","-i {dev} -c 30 icmp"],
 tshark:["-i {dev} -c 30"],ngrep:["-d {dev} -q -n 20 GET"],nmap:["-sn {net}","-F {gw}","-sV -F {gw}"],iperf3:["-c <server> -t 5","-c <server> -R -t 5","-s"],
 iftop:["-i {dev}"],nethogs:["{dev}"],nload:[""],vnstat:["","-d","-h","-m"],"avahi-resolve-address":["{gw}"],nmblookup:["-A {gw}"]};
async function loadTools(){try{const t=await api("/api/tools");S.tools=t.tools;renderTools(t);fillConsole()}catch(e){fail("#tools",e)}}
function renderTools(t){$("#tcount").textContent=`${t.installed} of ${t.tools.length} installed`;
 const cats={};t.tools.forEach(x=>(cats[x.category]=cats[x.category]||[]).push(x));
 let x=t.install_cmd?`<div class="sbody" style="padding-bottom:4px"><div class="soft">Install the missing ones on Debian or Ubuntu:</div><div class="copy"><code id="icmd">${esc(t.install_cmd)}</code><button class="btn sm" id="copyb">Copy</button></div></div>`:"";
 x+=Object.entries(cats).map(([c,a])=>`<div class="ghead" style="padding-top:16px">${esc(c)}</div><div class="toolgrid">${a.map(i=>`<div class="tool ${i.installed?"on":"off"}">${ic(i.installed?"check":"x")}<div><b>${esc(i.cmd)}</b><div>${esc(i.desc)}</div></div></div>`).join("")}</div>`).join("");
 $("#tools").innerHTML=x;
 const cb=$("#copyb");if(cb)cb.onclick=async()=>{try{await navigator.clipboard.writeText(t.install_cmd);cb.textContent="Copied"}catch(e){const r=document.createRange();r.selectNodeContents($("#icmd"));getSelection().removeAllRanges();getSelection().addRange(r);cb.textContent="Selected"}setTimeout(()=>cb.textContent="Copy",1500)}}
function fillConsole(){const sel=$("#ctool"),cur=sel.value;
 sel.innerHTML=S.tools.map(t=>`<option value="${esc(t.cmd)}"${t.installed?"":" disabled"}>${esc(t.cmd)}${t.installed?"":" (not installed)"}</option>`).join("");
 const first=S.tools.find(t=>t.installed);sel.value=cur&&S.tools.find(t=>t.cmd===cur&&t.installed)?cur:(first?first.cmd:"");showPresets()}
function vars(){const o=S.ov||{},dev=o.primary||"eth0",me=(o.interfaces||[]).find(i=>i.name===dev);
 return {gw:o.gateway?.gateway||"192.168.1.1",dev,net:S.neigh?.network||(me&&me.ipv4[0])||"192.168.1.0/24"}}
function showPresets(){const t=$("#ctool").value,v=vars();
 $("#cpresets").innerHTML=(PRESETS[t]||[]).map(p=>{const a=p.replace(/\{(\w+)\}/g,(_,k)=>v[k]);return `<button data-preset="${esc(a)}">${esc((t+" "+a).trim())}</button>`}).join("")}
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
  if(!S.tif||!S.traffic[S.tif])S.tif=names[0];sel.value=S.tif;if(S.view==="traffic")drawChart()}catch(e){}}
function drawChart(){const c=$("#tchart");if(!c||!c.clientWidth)return;const d=(S.traffic||{})[S.tif]||[],dpr=window.devicePixelRatio||1,w=c.clientWidth,h=300;
 const cs=getComputedStyle(document.documentElement),V=k=>cs.getPropertyValue(k).trim();
 c.width=w*dpr;c.height=h*dpr;const x=c.getContext("2d");x.scale(dpr,dpr);x.clearRect(0,0,w,h);
 const max=Math.max(1250,...d.map(p=>Math.max(p[1],p[2])))*1.15,N=120,top=6,bh=h-26,left=0;
 x.font="11px "+V("--sans");x.lineWidth=1;
 for(let i=0;i<=4;i++){const y=top+bh*i/4;x.strokeStyle=V("--line-2");x.beginPath();x.moveTo(left,y+.5);x.lineTo(w,y+.5);x.stroke();x.fillStyle=V("--ink-3");if(i<4)x.fillText(rate(max*(1-i/4)),left+2,y+13)}
 x.fillStyle=V("--ink-3");x.fillText("2 min ago",2,h-6);x.textAlign="right";x.fillText("now",w-2,h-6);x.textAlign="left";
 const line=(k,col)=>{if(!d.length)return;x.strokeStyle=col;x.lineWidth=2;x.lineJoin="round";x.beginPath();d.forEach((p,i)=>{const px=w-(d.length-1-i)*(w/(N-1)),py=top+bh*(1-p[k]/max);i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke()};
 line(1,V("--rx"));line(2,V("--tx"));
 const last=d[d.length-1],pk=d.reduce((m,p)=>Math.max(m,p[1],p[2]),0);
 $("#tnow").innerHTML=`<div class="meter"><dt><span class="sw" style="background:var(--rx)"></span>Download</dt><dd>${last?rate(last[1]):"…"}</dd></div><div class="meter"><dt><span class="sw" style="background:var(--tx)"></span>Upload</dt><dd>${last?rate(last[2]):"…"}</dd></div><div class="meter"><dt>Peak, last 2 minutes</dt><dd>${rate(pk)}</dd></div>`}

/* ---------- wiring ---------- */
async function runAll(){const b=$("#runall");b.disabled=true;b.querySelector("span").textContent="Checking…";
 await loadOverview();loadWifi();loadTools();loadSockets();
 await Promise.allSettled([loadHealth(),loadNeighbors(),loadPath()]);
 b.disabled=false;b.querySelector("span").textContent="Run checks"}
document.addEventListener("click",e=>{
 const nav=e.target.closest("[data-go]");if(nav){go(nav.dataset.go);return}
 const hb=e.target.closest("[data-host]");if(hb){showHost(hb.dataset.host);return}
 const sn=e.target.closest("[data-stage]");if(sn){const g=$("#g-"+sn.dataset.stage);if(g){g.scrollIntoView({behavior:"smooth",block:"center"});g.classList.remove("flash");void g.offsetWidth;g.classList.add("flash")}return}
 const p=e.target.closest("[data-preset]");if(p){$("#cargs").value=p.dataset.preset;consoleRun()}});
$("#runall").onclick=runAll;$("#rescan").onclick=loadNeighbors;$("#resock").onclick=loadSockets;$("#nfilter").oninput=renderNeigh;
$("#pathf").onsubmit=e=>{e.preventDefault();loadPath()};
$("#tiface").onchange=e=>{S.tif=e.target.value;drawChart()};
$("#ctool").onchange=showPresets;$("#crun").onclick=consoleRun;$("#cclear").onclick=()=>{$("#cout").textContent="";delete $("#cout").dataset.used};
$("#cargs").onkeydown=e=>{if(e.key==="Enter")consoleRun()};
window.addEventListener("hashchange",()=>go(location.hash.slice(1)));
window.addEventListener("resize",()=>{if(S.view==="traffic")drawChart()});
matchMedia("(prefers-color-scheme: dark)").addEventListener("change",()=>setTheme(document.documentElement.dataset.theme));
setInterval(pollTraffic,1000);
setInterval(()=>{if($("#auto").checked){loadHealth();loadSockets()}},60000);
setTheme(document.documentElement.dataset.theme);go(location.hash.slice(1)||"diagnosis");renderVerdictWaiting();renderFacts();
runAll();
</script></body></html>
"""

if __name__ == "__main__":
    main()
