#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Port scanning + the Sunlight/Echo adaptive probe (المحقق كونان).

What this module does — and what it does NOT do:
- It connects to TCP ports of the target host and records which ones
  answer (open), with the public service banner the port itself sends.
  This is the same kind of reachability check `nmap` and every
  defensive scanner performs.
- For every open port it then tries a plain HTTP request with the
  site's Host header: does this door serve the site's own public
  pages? Those are the "entry points" — doors the site itself opens
  to the public.
- It NEVER tries to log in, NEVER sends credentials, NEVER bypasses
  authentication or a firewall, NEVER exploits a service, and NEVER
  hides or rotates its identity to evade detection. A closed door
  stays closed: the report says so, honestly.

The Sunlight/Echo method (developer's idea, documented here for a
future patent filing): like sunlight blocked by a big wall, the probe
shines from every door at once; like a sound sent out and its echo
listened for, every answer is listened to and the next probe adapts
to what the echo said. Phase 1 knocks on the common doors. Phase 2
listens to the echoes: if a door answers, its neighbours and related
doors are tried next (a web port open on 8080 suggests 8000, 8888,
8443...). Phase 3 checks each open door with a real HTTP request to
see whether the site's own public light shines through it. The method
is fully described here so the developer can file it as an invention;
the filing itself is a legal process (patent office / patent agent),
not something this tool does.

Authorization: port scanning is an ACTIVE test. It runs only on the
user's own site or a site with written authorization — the mega scan
asks once at the start and skips this module otherwise.
"""
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPCbind",
    123: "NTP", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL", 2181: "Zookeeper",
    2222: "SSH-alt", 2375: "Docker", 2376: "Docker-TLS",
    3000: "Node/Dev", 3306: "MySQL", 3389: "RDP", 4369: "Erlang",
    5000: "Flask/UPnP", 5432: "PostgreSQL", 5672: "RabbitMQ",
    5900: "VNC", 5985: "WinRM", 6379: "Redis", 7001: "Cassandra",
    8000: "HTTP-alt", 8008: "HTTP-alt", 8009: "AJP", 8080: "HTTP-proxy",
    8081: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt",
    9000: "PHP-FPM/Sonar", 9042: "Cassandra", 9090: "HTTP-alt",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch",
    9443: "HTTPS-alt", 10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB",
}

# If a door answers, its neighbours are worth trying next.
RELATED_PORTS = {
    80: [8000, 8008, 8080, 8081, 8888, 8443, 9000],
    443: [8443, 9443, 8080, 8000],
    8080: [8000, 8008, 8081, 8888, 8443, 9000, 9090],
    8443: [443, 9443, 8080, 8000],
    22: [2222, 2200],
    3306: [3307, 33060],
    5432: [5433],
    6379: [6380],
    27017: [27018, 28017],
    9200: [9300],
    3389: [3390],
    5900: [5901],
    21: [2121],
    25: [587, 465, 2525],
}


def _grab_banner(sock, timeout=0.6):
    """Read the public banner a service sends on connect (max 120 chars)."""
    try:
        sock.settimeout(timeout)
        data = sock.recv(256)
        text = data.decode("utf-8", errors="ignore").strip()
        return text.replace("\n", " ").replace("\r", " ")[:120]
    except Exception:
        return ""


def _check_port(host, port, timeout=0.4):
    """One TCP connect. Returns a dict for open ports, else None."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return None
    banner = _grab_banner(sock)
    try:
        sock.close()
    except Exception:
        pass
    return {"port": port, "service": COMMON_PORTS.get(port, "unknown"),
            "state": "open", "banner": banner}


def scan_ports(host, ports, timeout=0.4, workers=30, progress=None):
    """Connect-scan a list of ports. Returns the open ones (sorted)."""
    ports = sorted(set(int(p) for p in ports if 0 < int(p) < 65536))
    found = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check_port, host, p, timeout): p for p in ports}
        for fut in futures:
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                found.append(res)
            if progress:
                try:
                    progress()
                except Exception:
                    pass
    return sorted(found, key=lambda r: r["port"])


def probe_entry_points(host, open_ports, url, timeout=5):
    """Try a plain HTTP request through each open door.

    Returns one entry per port that answered HTTP at all: the status
    and whether the response looks like the target site's own public
    pages (the site's host or title appears). This only reads public
    pages — no login, no credentials, no bypass.
    """
    entries = []
    target_host = url.split("/")[2] if "://" in url else host
    for item in open_ports:
        port = item["port"]
        scheme = "https" if port in (443, 8443, 9443, 2083, 2087) else "http"
        path = "%s://%s:%d/" % (scheme, host, port)
        try:
            ctx = ssl._create_unverified_context()
            req = socket.create_connection((host, port), timeout=timeout)
            if scheme == "https":
                req = ctx.wrap_socket(req, server_hostname=host)
            req.settimeout(timeout)
            req.sendall(("GET / HTTP/1.0\r\nHost: %s\r\n"
                         "User-Agent: Conan-Detective\r\n\r\n"
                         % target_host).encode())
            data = b""
            while len(data) < 8192:
                chunk = req.recv(4096)
                if not chunk:
                    break
                data += chunk
            req.close()
            text = data.decode("utf-8", errors="ignore")
            status = ""
            if text.startswith("HTTP/"):
                status = text.split(" ", 2)[1] if len(text.split(" ")) > 1 else ""
            serves = (target_host in text) or ("<title" in text.lower())
            entries.append({"port": port, "scheme": scheme, "status": status,
                            "serves_site": bool(serves),
                            "snippet": text[:120].replace("\n", " ")})
        except Exception as exc:
            entries.append({"port": port, "scheme": scheme, "status": "",
                            "serves_site": False, "error": str(exc)[:80]})
    return entries


def adaptive_probe(host, url, timeout=0.4, common_ports=None, progress=None):
    """The Sunlight/Echo adaptive probe. Three phases:

    1. Common doors — scan the well-known ports (the "light" from
       every door at once).
    2. Echo adaptation — for each door that answered, try its related
       neighbours (the echo tells the probe where to shine next).
    3. Entry points — try a plain HTTP request through every open
       door and record which ones serve the site's public pages.
    """
    common = sorted(common_ports if common_ports is not None
                    else COMMON_PORTS)
    phase1 = scan_ports(host, common, timeout=timeout, progress=progress)
    tried = set(common)
    related = []
    for item in phase1:
        for p in RELATED_PORTS.get(item["port"], []):
            if p not in tried:
                related.append(p)
                tried.add(p)
    phase2 = scan_ports(host, related, timeout=timeout, progress=progress) \
        if related else []
    all_open = sorted(phase1 + phase2, key=lambda r: r["port"])
    entries = probe_entry_points(host, all_open, url, timeout=5) \
        if all_open else []
    return {
        "method": "Sunlight/Echo adaptive probe",
        "phase1_common": len(common),
        "phase2_related": len(related),
        "open_ports": all_open,
        "open_count": len(all_open),
        "entry_points": entries,
        "doors_serving_site": [e["port"] for e in entries
                               if e.get("serves_site")],
    }


def scan_all_ports(host, timeout=0.4, workers=60, progress=None):
    """Full scan of all 65535 ports. Slow by nature — minutes, not
    seconds. Only run on an authorized target, with the user's choice.
    """
    return scan_ports(host, range(1, 65536), timeout=timeout,
                      workers=workers, progress=progress)
