"""Start the built NetPane.exe on a real Windows machine and check every API endpoint.

Usage: python packaging/smoke_test.py dist/NetPane.exe
Exits non-zero if anything that should always work on Windows doesn't.
"""
import json
import subprocess
import sys
import time
import urllib.request

EXE = sys.argv[1]
BASE = "http://127.0.0.1:8765"
failures = []


def get(path, timeout=240):
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        body = r.read().decode("utf-8", "replace")
    return json.loads(body) if path.startswith("/api/") and not path.endswith(".txt") else body


def post(path, data):
    req = urllib.request.Request(BASE + path, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def check(cond, label, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + (f"  [{detail}]" if detail else ""))
    if not cond:
        failures.append(label)


log = open("netpane-smoke.log", "w")
proc = subprocess.Popen([EXE, "--no-browser", "--port", "8765"], stdout=log, stderr=subprocess.STDOUT)
try:
    for _ in range(90):
        try:
            get("/api/tools", 5)
            break
        except Exception:  # noqa: BLE001
            time.sleep(1)
    else:
        print("NetPane.exe never started listening")
        sys.exit(1)

    print("\n== overview")
    o = get("/api/overview")
    for i in o["interfaces"]:
        print(f"    {i['name']:<34} {i['state']:<5} {','.join(i['ipv4']) or '-':<20} mtu {i['mtu']} virt={i['virtual']} wifi={i['wireless']} {i['driver'] or ''}")
    print("    gateway:", o["gateway"], " dns:", o["dns"])
    print("    routes:", [(r["dst"], r.get("gateway"), r["dev"]) for r in o["routes"]["ipv4"]][:8])
    check(o["platform"] == "windows", "platform is windows")
    check(len(o["interfaces"]) > 0, "interfaces listed", len(o["interfaces"]))
    check(bool(o["gateway"]), "default gateway found from Get-NetRoute")
    check(bool(o["dns"]["resolv_conf"]), "DNS servers found from Get-DnsClientServerAddress", o["dns"]["resolv_conf"])
    check(o["primary"] is not None, "primary interface chosen", o["primary"])

    print("\n== health")
    h = get("/api/health")
    for c in h["checks"]:
        print(f"    {c['status']:<5} {c['name']:<24} {c['detail'][:110]}")
    print("    verdict:", h["verdict"]["headline"])
    st = {c["name"]: c["status"] for c in h["checks"]}
    check(len(h["checks"]) == 13, "13 checks ran")
    check(st.get("Physical link") != "fail", "physical link not failed")
    check(st.get("IP address") == "pass", "IP address passes")
    check(st.get("Default route") == "pass", "default route passes")
    check(st.get("Gateway ARP") == "pass", "gateway found in the neighbour table")
    check(st.get("TCP egress") == "pass", "TCP 443 out works")
    check(st.get("DNS servers") == "pass", "built-in DNS query works against the runner's DNS")
    check(st.get("Name resolution") == "pass", "system name resolution works")
    check(st.get("HTTPS") == "pass", "HTTPS works through the Windows certificate store")

    print("\n== console")
    r = post("/api/run", {"tool": "ping", "args": "-n 2 127.0.0.1"})
    print("   ", r["cmd"], "rc", r["rc"])
    check(r["rc"] == 0 and "TTL=" in r["out"].upper(), "ping.exe runs through the console")
    r = post("/api/run", {"tool": "ping", "args": "-t 127.0.0.1"})
    check("-t" not in r["cmd"].split() and "-n" in r["cmd"], "ping -t is capped instead of running forever", r["cmd"])
    r = post("/api/run", {"tool": "ipconfig", "args": "/all"})
    check(r["rc"] == 0 and len(r["out"]) > 100, "ipconfig /all runs")
    r = post("/api/run", {"tool": "rm", "args": "-rf /"})
    check("error" in r, "unknown tools are refused")

    print("\n== sockets / traffic / wifi / tools")
    s = get("/api/sockets")
    mine = [x for x in s["listening"] if x["local"].endswith(":8765")]
    check(bool(mine), "NetPane's own port shows as listening", mine[:1])
    check(any(x["process"] for x in s["all"]), "program names resolved for sockets")
    t = get("/api/traffic")
    check(len(t) > 0, "traffic counters sampled", list(t)[:3])
    w = get("/api/wifi")
    check(isinstance(w.get("networks"), list), "wifi endpoint answers", (w.get("note") or "")[:80])
    tl = get("/api/tools")
    have = {x["cmd"] for x in tl["tools"] if x["installed"]}
    check({"ping", "tracert", "ipconfig", "netsh", "netstat", "nslookup"} <= have, "built-in Windows tools detected", sorted(have))

    print("\n== path")
    p = get("/api/path?target=127.0.0.1")
    check(len(p["hops"]) >= 1, "tracert parsed", p["hops"][:2])

    print("\n== neighbours")
    n = get("/api/neighbors")
    print("   ", n.get("method"), n.get("network"), [(x["ip"], x["state"], x["kind"]) for x in n.get("hosts", [])][:8])
    check(not n.get("error") and len(n["hosts"]) >= 1, "subnet sweep ran", n.get("count"))

    print("\n== report")
    rep = get("/api/report.txt")
    check("NETPANE NETWORK REPORT" in rep, "text report generated")
    page = get("/")
    check("<title>NetPane</title>" in page, "dashboard page served")
finally:
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    log.close()
    print("\n== NetPane console output")
    print(open("netpane-smoke.log", errors="replace").read()[-3000:])

print(f"\n{len(failures)} failure(s)" + (": " + ", ".join(failures) if failures else ""))
sys.exit(1 if failures else 0)
