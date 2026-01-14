import subprocess, sys, platform, re, requests, time, socket
from urllib.parse import urlparse

# ---------- target handling ----------

def normalize_target(target: str) -> str:
    """Accept full URLs or plain hosts/IPs and return a hostname/IP for traceroute."""
    t = (target or "").strip()
    if not t:
        return t
    if re.match(r"^[a-zA-Z]+://", t):
        p = urlparse(t)
    else:
        # allow strings like example.com:443/path too
        p = urlparse("//" + t)
    host = p.netloc or p.path or t
    # strip IPv6 brackets and port
    host = host.strip("[]")
    if ":" in host and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        host = host.split(":", 1)[0]
    return host


def _resolve_ipv4(host: str) -> str:
    """Prefer IPv4 address; fall back to original host on failure."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return host

# ---------- parsers ----------

_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

# Windows `tracert` line with three probes:
# "  1     <1 ms     1 ms     2 ms  172.17.88.1"
_WIN_TRIPS = re.compile(
    r"^\s*(\d+)\s+"
    r"(?:(<\d+|\d+)\s*ms|\*)\s+"
    r"(?:(<\d+|\d+)\s*ms|\*)\s+"
    r"(?:(<\d+|\d+)\s*ms|\*)\s+"
    r"(.+)$"
)
_WIN_LINE_FALLBACK = re.compile(r"^\s*(\d+)\s+(.+)$")

def _to_ms_win(tok: str | None):
    if not tok or tok == "*":
        return None
    tok = tok.replace("<", "")
    try:
        return float(tok)
    except Exception:
        return None

def _parse_tracert_win(text: str):
    hops = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("tracing route", "over a maximum")):
            continue
        if "request timed out" in line.lower():
            m = _WIN_LINE_FALLBACK.match(line)
            if m:
                hop_no = int(m.group(1))
                hops.append({"hop": hop_no, "ip": "*", "host": "*", "rtt_ms": None})
            continue

        m = _WIN_TRIPS.match(line)
        if m:
            hop_no = int(m.group(1))
            t1 = _to_ms_win(m.group(2))
            t2 = _to_ms_win(m.group(3))
            t3 = _to_ms_win(m.group(4))
            tail = m.group(5).strip()
            ip = (_IP_RE.search(tail).group(1) if _IP_RE.search(tail) else "*")
            times = [t for t in (t1, t2, t3) if t is not None]
            rtt = sum(times) / len(times) if times else None
            hops.append({"hop": hop_no, "ip": ip, "host": ip if ip != "*" else tail, "rtt_ms": rtt})
            continue

        fm = _WIN_LINE_FALLBACK.match(line)
        if fm:
            hop_no = int(fm.group(1))
            tail = fm.group(2).strip()
            ip = (_IP_RE.search(tail).group(1) if _IP_RE.search(tail) else "*")
            hops.append({"hop": hop_no, "ip": ip, "host": ip if ip != "*" else tail, "rtt_ms": None})
    return hops

def _parse_traceroute_unix(text: str):
    hops = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("traceroute to",)):
            continue
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        hop_no = int(m.group(1))
        tail = m.group(2)
        ipm = _IP_RE.search(tail)
        ip = ipm.group(1) if ipm else "*"
        times = [float(v) for v in re.findall(r"(\d+(?:\.\d+)?)\s*ms", tail)]
        rtt = (sum(times) / len(times)) if times else None
        hops.append({"hop": hop_no, "ip": ip, "host": ip, "rtt_ms": rtt})
    return hops

# ---------- traceroute runner ----------

def run_traceroute(host_or_url: str, max_hops: int = 20, timeout_sec: int = 60, per_hop_ms: int = 900):
    """
    per_hop_ms: per-probe wait (ms). Shorter waits avoid the whole command exceeding timeout.
    """
    host_in = normalize_target(host_or_url)
    host = _resolve_ipv4(host_in)  # prefer IPv4 (fewer surprises)

    sys_plat = platform.system().lower()
    if "windows" in sys_plat:
        # -d no reverse DNS; -h hops; -w per-hop wait in ms
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(per_hop_ms), host]
        tool = "tracert"
    else:
        # -n numeric, -m max hops, -w wait per probe (sec), -q 3 probes
        wait_s = max(0.2, per_hop_ms / 1000.0)
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(wait_s), "-q", "3", host]
        tool = "traceroute"

    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT,
            timeout=timeout_sec, text=True,
            encoding="utf-8", errors="ignore"
        )
    except Exception as e:
        return {"host": host_in, "tool": tool, "error": str(e), "raw": ""}

    if tool == "tracert":
        hops = _parse_tracert_win(out)
    else:
        hops = _parse_traceroute_unix(out)

    return {"host": host_in, "tool": tool, "hops": hops, "raw": out}

# ---------- geo helpers ----------

def geolocate_ip(ip: str, timeout=6.0):
    """Return dict with country, city, lat, lon, org using ip-api.com (no API key)."""
    try:
        if not ip or ip == "*":
            raise ValueError("no ip")
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,org,query"
        r = requests.get(url, timeout=timeout)
        j = r.json()
        if j.get("status") == "success":
            return {
                "ip": j.get("query"), "country": j.get("country"),
                "city": j.get("city"), "lat": j.get("lat"), "lon": j.get("lon"),
                "org": j.get("org")
            }
    except Exception:
        pass
    return {"ip": ip, "country": None, "city": None, "lat": None, "lon": None, "org": None}

def enrich_hops_with_geo(hops):
    enriched = []
    for h in hops:
        ip = h.get("ip")
        info = geolocate_ip(ip) if ip and ip != "*" else {"ip": ip, "country": None, "city": None, "lat": None, "lon": None, "org": None}
        e = dict(h); e.update(info)
        enriched.append(e)
        time.sleep(0.15)  # be polite to the free API
    return enriched
