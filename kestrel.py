#!/usr/bin/env python3
"""
KESTREL // Cyber Threat Observatory
-----------------------------------
A zero-dependency (Python 3.7+ stdlib only) feed proxy and static server.

It pulls free OSINT threat feeds, normalises them, caches them in memory and
on disk, geolocates IPs in the background (ip-api.com batch endpoint), and
serves the single-page dashboard from ./static.

    python kestrel.py               # http://127.0.0.1:8787
    python kestrel.py --port 9000 --no-browser
"""
import argparse
import gzip
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(ROOT, "static")
CACHE_DIR = os.path.join(ROOT, ".cache")
UA = "KESTREL-ThreatObservatory/1.0 (personal OSINT dashboard)"
os.makedirs(CACHE_DIR, exist_ok=True)

with open(os.path.join(ROOT, "data", "countries.json"), encoding="utf-8") as f:
    COUNTRIES = json.load(f)


# --------------------------------------------------------------------------
# Config: optional API keys from config.json or environment variables
# --------------------------------------------------------------------------
def load_config():
    cfg = {}
    path = os.path.join(ROOT, "config.json")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:  # noqa: BLE001
            print("[config] could not parse config.json:", e)
    return {k: str(v).strip() for k, v in cfg.items() if isinstance(v, (str, int, float)) and v != ""}


# No API keys are used anywhere: every feed is a free public source.
CONFIG = load_config()


# --------------------------------------------------------------------------
# HTTP helpers (urllib first, curl.exe fallback for odd TLS chains on Windows)
# --------------------------------------------------------------------------
def _curl(url, headers, data, timeout):
    cmd = ["curl", "-sS", "-L", "--compressed", "-m", str(timeout), "-f"]
    for k, v in headers.items():
        if k.lower() == "accept-encoding":
            continue
        cmd += ["-H", "%s: %s" % (k, v)]
    if data is not None:
        cmd += ["--data-binary", "@-"]
    cmd.append(url)
    p = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout + 5)
    if p.returncode != 0:
        raise IOError("curl failed (%s): %s" % (p.returncode, p.stderr.decode("utf8", "replace")[:200]))
    return p.stdout


def http_get(url, headers=None, data=None, timeout=30, allow_error_body=False):
    h = {"User-Agent": UA, "Accept-Encoding": "gzip"}
    h.update(headers or {})
    if isinstance(data, str):
        data = data.encode("utf8")
    try:
        req = urllib.request.Request(url, headers=h, data=data)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            if r.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            return body
    except urllib.error.HTTPError as e:
        if allow_error_body:
            body = e.read()
            if e.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            return body
        raise
    except (urllib.error.URLError, ssl.SSLError) as e:
        if "CERTIFICATE" in str(e).upper() or isinstance(getattr(e, "reason", None), ssl.SSLError):
            return _curl(url, h, data, timeout)
        raise


def get_json(url, **kw):
    return json.loads(http_get(url, **kw).decode("utf8", "replace"))


def get_retry(fn, url, tries=3, waits=(5, 15), **kw):
    """For sources that throttle or briefly fail (NVD without a key answers 503/429/403 under load): try again
    after a short wait instead of giving up on the first refusal."""
    for n in range(tries):
        try:
            return fn(url, **kw)
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429, 500, 502, 503, 504) or n == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError, OSError):
            if n == tries - 1:
                raise
        time.sleep(waits[min(n, len(waits) - 1)])


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_utc():
    return datetime.now(timezone.utc)


def parse_dt(s):
    """Best-effort parse of the many date formats feeds use; returns ISO string or None."""
    if not s:
        return None
    s = s.strip()
    try:
        return iso(parsedate_to_datetime(s))
    except Exception:  # noqa: BLE001
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d"):
        try:
            d = datetime.strptime(s.replace("Z", "+0000") if "%z" in fmt else s.replace("Z", ""), fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return iso(d)
        except ValueError:
            continue
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return iso(d)
    except ValueError:
        return None


def norm_ip(s):
    """SANS ISC zero-pads octets (e.g. 013.094.001.002); normalise and validate."""
    try:
        s = ".".join(str(int(p)) for p in s.strip().split(".")) if s.count(".") == 3 else s.strip()
        ip = ipaddress.ip_address(s)
        return str(ip) if ip.is_global else None
    except (ValueError, AttributeError):
        return None


def jitter(seed, spread=1.6):
    """Deterministic offset so country-centroid markers don't stack perfectly."""
    h = hashlib.md5(seed.encode("utf8")).digest()
    return ((h[0] / 255.0) - 0.5) * spread, ((h[1] / 255.0) - 0.5) * spread


def country_geo(cc, seed):
    c = COUNTRIES.get((cc or "").upper())
    if not c:
        return None
    dy, dx = jitter(seed)
    return {"lat": round(c[0] + dy, 4), "lon": round(c[1] + dx, 4), "cc": cc.upper(), "country": c[2], "approx": True}


# --------------------------------------------------------------------------
# Cache: in-memory with disk persistence; serves stale data if refresh fails
# --------------------------------------------------------------------------
CACHE_SCHEMA = 3  # bump when a feed's output shape changes so old disk caches are ignored


class Cache:
    def __init__(self):
        self.mem = {}
        self.locks = {}
        self.errors = {}
        self.glock = threading.Lock()

    def _lock(self, key):
        with self.glock:
            return self.locks.setdefault(key, threading.Lock())

    def _disk(self, key):
        return os.path.join(CACHE_DIR, "feed_%s.json" % key)

    def get(self, key, ttl, fn):
        ent = self.mem.get(key)
        if ent is None and os.path.exists(self._disk(key)):
            try:
                with open(self._disk(key), encoding="utf-8") as f:
                    ent = json.load(f)
                if ent.get("v") != CACHE_SCHEMA:
                    ent = None  # written by an older version with a different data shape
                else:
                    self.mem[key] = ent
            except Exception:  # noqa: BLE001
                ent = None
        if ent and time.time() - ent["ts"] < ttl:
            return ent
        if ent:
            # stale-while-revalidate: answer instantly with the old copy, refresh in the background
            lock = self._lock(key)
            if not lock.locked():
                threading.Thread(target=self._refresh, args=(key, ttl, fn), daemon=True).start()
            return ent
        return self._refresh(key, ttl, fn)

    def _refresh(self, key, ttl, fn):
        with self._lock(key):
            ent = self.mem.get(key)
            if ent and time.time() - ent["ts"] < ttl:
                return ent
            try:
                t0 = time.time()
                val = fn()
                ent = {"ts": time.time(), "updated": iso(now_utc()), "data": val, "ms": int((time.time() - t0) * 1000),
                       "v": CACHE_SCHEMA}
                self.mem[key] = ent
                self.errors.pop(key, None)
                try:
                    with open(self._disk(key), "w", encoding="utf-8") as f:
                        json.dump(ent, f)
                except Exception:  # noqa: BLE001
                    pass
                print("[feed] %-11s refreshed in %sms" % (key, ent["ms"]))
                return ent
            except Exception as e:  # noqa: BLE001
                self.errors[key] = {"error": str(e)[:300], "at": iso(now_utc())}
                print("[feed] %-11s FAILED: %s" % (key, str(e)[:200]))
                if ent:
                    return dict(ent, stale=True)
                raise


CACHE = Cache()


# --------------------------------------------------------------------------
# Background geolocation (ip-api.com batch: 100 IPs/request, 15 req/min, no key)
# --------------------------------------------------------------------------
class Geo:
    PATH = os.path.join(CACHE_DIR, "geo.json")
    FIELDS = "status,message,query,lat,lon,countryCode,country,city,isp,as"

    def __init__(self):
        self.db = {}
        self.pending = []
        self.pset = set()
        self.lock = threading.Lock()
        self.dirty = False
        self.last_error = None
        if os.path.exists(self.PATH):
            try:
                with open(self.PATH, encoding="utf-8") as f:
                    self.db = json.load(f)
            except Exception:  # noqa: BLE001
                self.db = {}
        threading.Thread(target=self._worker, daemon=True, name="geo").start()

    def lookup(self, ip, priority=False):
        if ip in self.db:
            return self.db[ip]
        with self.lock:
            if ip not in self.pset:
                self.pset.add(ip)
                if priority:
                    self.pending.insert(0, ip)
                else:
                    self.pending.append(ip)
        return None

    def enrich(self, items, field="ip"):
        for it in items:
            ip = it.get(field)
            if ip and not it.get("geo"):
                g = self.lookup(ip)
                if g:
                    it["geo"] = g
        return items

    def _worker(self):
        while True:
            batch = []
            with self.lock:
                while self.pending and len(batch) < 100:
                    ip = self.pending.pop(0)
                    batch.append(ip)
            if not batch:
                if self.dirty:
                    self._save()
                time.sleep(2)
                continue
            try:
                req = urllib.request.Request(
                    "http://ip-api.com/batch?fields=" + self.FIELDS,
                    data=json.dumps(batch).encode(), headers={"User-Agent": UA, "Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    res = json.loads(r.read().decode("utf8"))
                    remaining = int(r.headers.get("X-Rl", "10") or 10)
                    ttl = int(r.headers.get("X-Ttl", "60") or 60)
                for row in res:
                    q = row.get("query")
                    if row.get("status") == "success":
                        self.db[q] = {"lat": row["lat"], "lon": row["lon"], "cc": row.get("countryCode"),
                                      "country": row.get("country"), "city": row.get("city"),
                                      "isp": row.get("isp"), "as": row.get("as")}
                    else:
                        self.db[q] = None
                with self.lock:
                    for ip in batch:
                        self.pset.discard(ip)
                self.dirty = True
                self.last_error = None
                print("[geo]  located %d IPs (%d queued)" % (len(batch), len(self.pending)))
                time.sleep(ttl + 1 if remaining <= 1 else 4.2)
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)[:200]
                with self.lock:
                    self.pending = batch + self.pending
                time.sleep(30)

    def _save(self):
        try:
            tmp = self.PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.db, f)
            os.replace(tmp, self.PATH)
            self.dirty = False
        except Exception as e:  # noqa: BLE001
            print("[geo] save failed:", e)


GEO = Geo()

# DNS resolution for phishing / malware hostnames (background, cached)
DNS = {}
DNS_POOL = ThreadPoolExecutor(max_workers=8)


def _resolve(host):
    try:
        DNS[host] = norm_ip(socket.gethostbyname(host))
    except Exception:  # noqa: BLE001
        DNS[host] = None


def resolve_host(host):
    if host in DNS:
        return DNS[host]
    DNS[host] = None  # mark in-flight
    DNS_POOL.submit(_resolve, host)
    return None


def host_ip(host):
    ip = norm_ip(host)
    return ip if ip else resolve_host(host)


# --------------------------------------------------------------------------
# Feeds
# --------------------------------------------------------------------------
def feed_kev():
    d = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=60)
    v = sorted(d["vulnerabilities"], key=lambda x: x.get("dateAdded", ""), reverse=True)
    today = now_utc().date()

    def age(x):
        try:
            return (today - datetime.strptime(x["dateAdded"], "%Y-%m-%d").date()).days
        except Exception:  # noqa: BLE001
            return 9999

    recent = [x for x in v if age(x) <= 180]
    # weekly additions for the last 26 weeks (weeks start Monday)
    monday = today - timedelta(days=today.weekday())
    weeks = [monday - timedelta(weeks=i) for i in range(25, -1, -1)]
    weekly = {w: {"week": w.isoformat(), "all": 0, "ransomware": 0} for w in weeks}
    for x in v:
        try:
            d0 = datetime.strptime(x["dateAdded"], "%Y-%m-%d").date()
        except Exception:  # noqa: BLE001
            continue
        wk = d0 - timedelta(days=d0.weekday())
        if wk in weekly:
            weekly[wk]["all"] += 1
            if x.get("knownRansomwareCampaignUse") == "Known":
                weekly[wk]["ransomware"] += 1
    return {
        "weekly": [weekly[w] for w in weeks],
        "total": d.get("count", len(v)),
        "catalogVersion": d.get("catalogVersion"),
        "added7": sum(1 for x in v if age(x) <= 7),
        "added30": sum(1 for x in v if age(x) <= 30),
        "ransomware": sum(1 for x in v if x.get("knownRansomwareCampaignUse") == "Known"),
        "topVendors": Counter(x["vendorProject"] for x in recent).most_common(8),
        "items": [{
            "cve": x["cveID"], "vendor": x.get("vendorProject"), "product": x.get("product"),
            "name": x.get("vulnerabilityName"), "added": x.get("dateAdded"), "due": x.get("dueDate"),
            "ransomware": x.get("knownRansomwareCampaignUse") == "Known",
            "desc": (x.get("shortDescription") or "")[:400], "cwes": x.get("cwes") or [],
        } for x in v[:80]],
    }


def _cvss(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            arr = sorted(arr, key=lambda m: m.get("type") != "Primary")
            m = arr[0]
            cd = m.get("cvssData", {})
            return {"score": cd.get("baseScore"), "severity": cd.get("baseSeverity") or m.get("baseSeverity"),
                    "vector": cd.get("vectorString"), "version": cd.get("version")}
    return {"score": None, "severity": None, "vector": None, "version": None}


def feed_cves():
    end = now_utc()
    start = end - timedelta(days=3)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&pubStartDate=%s&pubEndDate=%s"
           % (start.strftime(fmt), end.strftime(fmt)))
    d = get_retry(get_json, url, timeout=90)
    items = []
    for w in d.get("vulnerabilities", []):
        c = w["cve"]
        if c.get("vulnStatus") == "Rejected":
            continue
        desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
        cv = _cvss(c.get("metrics", {}))
        cwe = []
        for wk in c.get("weaknesses", []):
            for dd in wk.get("description", []):
                if dd.get("value", "").startswith("CWE-"):
                    cwe.append(dd["value"])
        items.append({"id": c["id"], "published": parse_dt(c.get("published")), "status": c.get("vulnStatus"),
                      "desc": desc[:420], "cwe": sorted(set(cwe))[:3], **cv})
    items.sort(key=lambda x: x["published"] or "", reverse=True)
    sev = Counter((x["severity"] or "UNSCORED").upper() for x in items)
    # 3-hour publication bins by severity across the 72h window
    bins = [{"t": iso(start + timedelta(hours=3 * i)), "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNSCORED": 0}
            for i in range(24)]
    for x in items:
        try:
            i = int((datetime.strptime(x["published"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - start)
                    .total_seconds() // 10800)
        except (TypeError, ValueError):
            continue
        if 0 <= i < 24:
            k = (x["severity"] or "UNSCORED").upper()
            bins[i][k if k in bins[i] else "UNSCORED"] += 1
    cwes = Counter(c for x in items for c in x["cwe"] if c not in ("CWE-Other",)).most_common(10)
    return {"total": len(items), "windowHours": 72, "severity": dict(sev), "timeline": bins, "cwes": cwes,
            "items": items[:400]}


def feed_ransomware():
    d = get_json("https://api.ransomware.live/v2/recentvictims", timeout=45)
    items = []
    for x in d:
        cc = (x.get("country") or "").upper()
        url = x.get("url") or ""
        items.append({
            "victim": x.get("victim") or "?", "group": x.get("group") or "?", "cc": cc,
            "sector": x.get("activity") if x.get("activity") not in (None, "", "Not Found") else None,
            "discovered": parse_dt(x.get("discovered")), "attackdate": parse_dt(x.get("attackdate")),
            "domain": x.get("domain") or None,
            "url": url if url.startswith("https://www.ransomware.live/") else None,
            "geo": country_geo(cc, (x.get("victim") or "") + (x.get("group") or "")),
        })
    items.sort(key=lambda x: x["discovered"] or "", reverse=True)
    cutoff = iso(now_utc() - timedelta(hours=24))
    # 6-hour bins of leak-site claims over the last 4 days, with the busiest group per bin
    t0 = now_utc().replace(minute=0, second=0, microsecond=0)
    t0 = t0 - timedelta(hours=t0.hour % 6) - timedelta(hours=6 * 15)
    timeline = [{"t": iso(t0 + timedelta(hours=6 * i)), "count": 0, "groups": Counter()} for i in range(16)]
    for x in items:
        try:
            i = int((datetime.strptime(x["discovered"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - t0)
                    .total_seconds() // 21600)
        except (TypeError, ValueError):
            continue
        if 0 <= i < 16:
            timeline[i]["count"] += 1
            timeline[i]["groups"][x["group"]] += 1
    for b in timeline:
        b["top"] = b["groups"].most_common(1)[0][0] if b["groups"] else None
        del b["groups"]
    return {
        "timeline": timeline,
        "items": items,
        "last24h": sum(1 for x in items if (x["discovered"] or "") >= cutoff),
        "groups": Counter(x["group"] for x in items).most_common(10),
        "countries": Counter(x["cc"] for x in items if x["cc"]).most_common(10),
        "sectors": Counter(x["sector"] for x in items if x["sector"]).most_common(8),
    }


def feed_c2():
    d = get_json("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    items = [{
        "ip": x["ip_address"], "port": x.get("port"), "status": x.get("status"), "malware": x.get("malware"),
        "asn": x.get("as_number"), "asName": x.get("as_name"), "cc": x.get("country"), "host": x.get("hostname"),
        "firstSeen": parse_dt(x.get("first_seen")), "lastOnline": x.get("last_online"),
    } for x in d]
    items.sort(key=lambda x: (x["status"] != "online", x["lastOnline"] or ""), reverse=False)
    return {"items": items, "online": sum(1 for x in items if x["status"] == "online"),
            "families": Counter(x["malware"] for x in items).most_common(8)}


PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP-alt", 110: "POP3",
              123: "NTP", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
              1723: "PPTP", 2323: "Telnet-alt", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "Postgres",
              5555: "ADB", 5900: "VNC", 6379: "Redis", 7547: "TR-069", 8080: "HTTP-proxy", 8443: "HTTPS-alt",
              8728: "MikroTik", 9200: "Elastic", 11211: "Memcached", 27017: "MongoDB", 37215: "Huawei HG",
              52869: "UPnP", 60001: "IoT", 2222: "SSH-alt", 8000: "HTTP-alt", 8888: "HTTP-alt", 9000: "HTTP-alt"}


def feed_attackers():
    top = get_json("https://isc.sans.edu/api/topips/records/100?json")
    ports = get_json("https://isc.sans.edu/api/topports/records/12?json")
    if isinstance(ports, dict):
        ports = [v for k, v in sorted(((k, v) for k, v in ports.items() if str(k).isdigit()),
                                      key=lambda kv: int(kv[0])) if isinstance(v, dict)]
    try:
        infocon = get_json("https://isc.sans.edu/api/infocon?json").get("status", "unknown")
    except Exception:  # noqa: BLE001
        infocon = "unknown"
    try:
        trend = get_json("https://isc.sans.edu/api/threatfeeds?json")
    except Exception:  # noqa: BLE001
        trend = []
    items = []
    for x in top:
        ip = norm_ip(str(x.get("source", "")))
        if ip:
            items.append({"ip": ip, "rank": x.get("rank"), "reports": int(x.get("reports") or 0),
                          "targets": int(x.get("targets") or 0)})
    et = http_get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt").decode("utf8", "replace")
    compromised = [{"ip": ip} for ip in (norm_ip(l) for l in et.split() if not l.startswith("#")) if ip]
    return {
        "infocon": infocon,
        "items": items,
        "ports": [{"port": int(p.get("targetport", 0)), "name": PORT_NAMES.get(int(p.get("targetport", 0)), ""),
                   "records": int(p.get("records") or 0), "sources": int(p.get("sources") or 0),
                   "targets": int(p.get("targets") or 0)} for p in ports],
        "trend": [{"date": t.get("date"), "count": t.get("count")} for t in trend][-30:] if isinstance(trend, list) else [],
        "compromised": compromised[:800],
    }


def feed_tor():
    txt = http_get("https://check.torproject.org/torbulkexitlist").decode("utf8", "replace")
    ips = [ip for ip in (norm_ip(l) for l in txt.split()) if ip]
    return {"items": [{"ip": ip} for ip in ips], "total": len(ips)}


def defang(u):
    return u.replace("http", "hxxp", 1).replace(".", "[.]")


def feed_phishing():
    txt = http_get("https://openphish.com/feed.txt").decode("utf8", "replace")
    urls = [u.strip() for u in txt.split() if u.strip().startswith("http")]
    items = []
    for u in urls[:500]:
        host = (urllib.parse.urlsplit(u).hostname or "").lower()
        if not host:
            continue
        items.append({"url": defang(u), "host": host})
    tlds = Counter(h["host"].rsplit(".", 1)[-1] for h in items)
    platforms = Counter(".".join(h["host"].split(".")[-2:]) for h in items)
    return {"items": items, "total": len(urls), "tlds": tlds.most_common(8), "platforms": platforms.most_common(8)}


def feed_outages():
    end = int(time.time())
    url = ("https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events?from=%d&until=%d&entityType=country&limit=200"
           % (end - 2 * 86400, end))
    d = get_json(url, timeout=60)
    agg = {}
    for e in d.get("data", []):
        cc = (e.get("location") or "").split("/")[-1].upper()
        a = agg.setdefault(cc, {"cc": cc, "name": e.get("location_name") or cc, "score": 0, "sources": set(),
                                "start": e.get("start"), "end": 0})
        a["score"] = max(a["score"], float(e.get("score") or 0))
        a["sources"].add(e.get("datasource"))
        a["start"] = min(a["start"] or e["start"], e.get("start") or a["start"])
        a["end"] = max(a["end"], (e.get("start") or 0) + (e.get("duration") or 0))
    items = []
    for a in agg.values():
        a["sources"] = sorted(s for s in a["sources"] if s)
        a["ongoing"] = a["end"] >= end - 1800
        a["startIso"] = iso(datetime.fromtimestamp(a["start"], timezone.utc)) if a["start"] else None
        a["durationH"] = round((a["end"] - (a["start"] or a["end"])) / 3600.0, 1)
        a["geo"] = country_geo(a["cc"], "outage" + a["cc"])
        if a["geo"]:
            a["geo"]["lat"], a["geo"]["lon"] = COUNTRIES[a["cc"]][0], COUNTRIES[a["cc"]][1]
        items.append(a)
    items.sort(key=lambda x: x["score"], reverse=True)
    return {"items": items, "ongoing": sum(1 for x in items if x["ongoing"])}


def feed_cables():
    d = get_json("https://www.submarinecablemap.com/api/v3/cable/cable-geo.json", timeout=60)
    feats = []
    for f in d.get("features", []):
        p = f.get("properties", {})
        feats.append({"type": "Feature", "geometry": f.get("geometry"),
                      "properties": {"name": p.get("name"), "color": p.get("color") or "#3fd0ff", "id": p.get("id")}})
    return {"type": "FeatureCollection", "features": feats}


NEWS_FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("The Record", "https://therecord.media/feed"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
]
TAGS = [("ransomware", r"ransom"), ("zero-day", r"zero[- ]day|0-day"), ("apt", r"\bAPT\d*\b|state[- ]sponsored|nation[- ]state"),
        ("breach", r"breach|leak|exposed"), ("exploit", r"exploit|RCE|remote code"), ("malware", r"malware|trojan|botnet|stealer|backdoor"),
        ("phishing", r"phish"), ("ics", r"\bICS\b|SCADA|industrial"), ("advisory", r"advisory|patch|update")]


def _tag(text):
    return [t for t, rx in TAGS if re.search(rx, text, re.I)][:3]


def _strip(s):
    s = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", s or "", flags=re.S)
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", unescape(unescape(s))).strip()


def _one_news(src, url):
    raw = http_get(url, timeout=30).decode("utf8", "replace")
    out = []
    for m in list(re.finditer(r"<item\b.*?</item>", raw, re.S))[:25]:
        blk = m.group(0)

        def tag(name):
            t = re.search(r"<%s\b[^>]*>(.*?)</%s>" % (name, name), blk, re.S)
            return t.group(1) if t else ""
        title = _strip(tag("title"))
        link = _strip(tag("link"))
        if not title or not link.startswith("http"):
            continue
        full = _strip(tag("description"))
        desc = full[:260]
        out.append({"source": src, "title": title, "link": link, "summary": desc, "text": full[:1500],
                    "published": parse_dt(_strip(tag("pubDate")) or _strip(tag("dc:date"))),
                    "cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", title + " " + full[:1500])))[:8],
                    "tags": _tag(title + " " + desc)})
    return out


def feed_news():
    items, errors = [], {}
    with ThreadPoolExecutor(max_workers=len(NEWS_FEEDS)) as ex:
        futs = {ex.submit(_one_news, s, u): s for s, u in NEWS_FEEDS}
        for fut, src in futs.items():
            try:
                items += fut.result()
            except Exception as e:  # noqa: BLE001
                errors[src] = str(e)[:120]
    if not items:
        raise IOError("all news feeds failed: %s" % errors)
    items.sort(key=lambda x: x["published"] or "", reverse=True)
    return {"items": items[:120], "errors": errors, "sources": [s for s, _ in NEWS_FEEDS]}


# ---- EPSS scores for the CVEs KESTREL is already tracking -------------------
def _feed_data(name):
    fn, ttl, _, _ = FEEDS[name]
    try:
        return CACHE.get(name, ttl, fn)["data"]
    except Exception:  # noqa: BLE001
        return {}


def feed_epss():
    """FIRST.org EPSS (exploit prediction) for recent KEV entries, critical CVEs and CVEs in the news."""
    kev, cves, news = _feed_data("kev"), _feed_data("cves"), _feed_data("news")
    cand = []
    for n in news.get("items", []):
        cand += n.get("cves", [])
    cand += [k["cve"] for k in kev.get("items", [])[:40]]
    scored = sorted([c for c in cves.get("items", []) if c.get("score")], key=lambda c: -c["score"])
    cand += [c["id"] for c in scored[:40]]
    seen, ids = set(), []
    for c in cand:
        if c not in seen:
            seen.add(c)
            ids.append(c)
    ids = ids[:120]
    out = {}
    for i in range(0, len(ids), 40):
        chunk = ids[i:i + 40]
        d = get_json("https://api.first.org/data/v1/epss?scope=time-series&cve=" + ",".join(chunk), timeout=40)
        for r in d.get("data", []):
            series = [{"date": t.get("date"), "epss": float(t.get("epss") or 0)} for t in (r.get("time-series") or [])]
            series.sort(key=lambda t: t["date"] or "")
            out[r["cve"]] = {"cve": r["cve"], "epss": float(r.get("epss") or 0),
                             "percentile": float(r.get("percentile") or 0), "date": r.get("date"),
                             "series": [t["epss"] for t in series][-30:]}
    return {"items": sorted(out.values(), key=lambda r: -r["epss"]), "candidates": len(ids)}


# ---- Cloud & SaaS provider status (public status pages) ---------------------
# Each provider is checked on its own, so one slow or broken status page never hides the others.
# level: "major" = outage (drives the flashing alert), "minor" = degraded / partial, "info" = notice.
STATUSPAGE = "statuspage"  # Atlassian Statuspage summary.json, used by many providers
CLOUD_SERVICES = [
    # id, name, kind, api url, public page, group
    ("aws", "AWS", "aws", "https://health.aws.amazon.com/public/currentevents", "https://health.aws.amazon.com/health/status", "Cloud & hosting"),
    ("azure", "Microsoft Azure", "rss", "https://azure.status.microsoft/en-us/status/feed/", "https://azure.status.microsoft/en-us/status", "Cloud & hosting"),
    ("gcp", "Google Cloud", "google", "https://status.cloud.google.com/incidents.json", "https://status.cloud.google.com/", "Cloud & hosting"),
    ("digitalocean", "DigitalOcean", STATUSPAGE, "https://status.digitalocean.com/api/v2/summary.json", "https://status.digitalocean.com/", "Cloud & hosting"),
    ("vercel", "Vercel", STATUSPAGE, "https://www.vercel-status.com/api/v2/summary.json", "https://www.vercel-status.com/", "Cloud & hosting"),
    ("netlify", "Netlify", STATUSPAGE, "https://www.netlifystatus.com/api/v2/summary.json", "https://www.netlifystatus.com/", "Cloud & hosting"),
    ("cloudflare", "Cloudflare", STATUSPAGE, "https://www.cloudflarestatus.com/api/v2/summary.json", "https://www.cloudflarestatus.com/", "Network & CDN"),
    ("fastly", "Fastly", STATUSPAGE, "https://www.fastlystatus.com/api/v2/summary.json", "https://www.fastlystatus.com/", "Network & CDN"),
    ("akamai", "Akamai", STATUSPAGE, "https://www.akamaistatus.com/api/v2/summary.json", "https://www.akamaistatus.com/", "Network & CDN"),
    ("okta", "Okta", "okta", "https://feeds.feedburner.com/OktaTrustRSS", "https://status.okta.com/", "Identity & security"),
    ("duo", "Cisco Duo", STATUSPAGE, "https://status.duo.com/api/v2/summary.json", "https://status.duo.com/", "Identity & security"),
    ("1password", "1Password", STATUSPAGE, "https://status.1password.com/api/v2/summary.json", "https://status.1password.com/", "Identity & security"),
    ("m365", "Microsoft 365", "m365", "https://status.cloud.microsoft/api/posts/m365Consumer", "https://status.cloud.microsoft/", "Work & comms"),
    ("gws", "Google Workspace", "google", "https://www.google.com/appsstatus/dashboard/incidents.json", "https://www.google.com/appsstatus/dashboard/", "Work & comms"),
    ("slack", "Slack", "slack", "https://slack-status.com/api/v2.0.0/current", "https://slack-status.com/", "Work & comms"),
    ("zoom", "Zoom", STATUSPAGE, "https://status.zoom.us/api/v2/summary.json", "https://status.zoom.us/", "Work & comms"),
    ("discord", "Discord", STATUSPAGE, "https://discordstatus.com/api/v2/summary.json", "https://discordstatus.com/", "Work & comms"),
    ("dropbox", "Dropbox", STATUSPAGE, "https://status.dropbox.com/api/v2/summary.json", "https://status.dropbox.com/", "Work & comms"),
    ("atlassian", "Atlassian", STATUSPAGE, "https://status.atlassian.com/api/v2/summary.json", "https://status.atlassian.com/", "Work & comms"),
    ("salesforce", "Salesforce", "salesforce", "https://api.status.salesforce.com/v1/incidents/active", "https://status.salesforce.com/", "Work & comms"),
    ("hubspot", "HubSpot", STATUSPAGE, "https://status.hubspot.com/api/v2/summary.json", "https://status.hubspot.com/", "Work & comms"),
    ("github", "GitHub", STATUSPAGE, "https://www.githubstatus.com/api/v2/summary.json", "https://www.githubstatus.com/", "Dev & ops"),
    ("datadog", "Datadog", STATUSPAGE, "https://status.datadoghq.com/api/v2/summary.json", "https://status.datadoghq.com/", "Dev & ops"),
    ("newrelic", "New Relic", STATUSPAGE, "https://status.newrelic.com/api/v2/summary.json", "https://status.newrelic.com/", "Dev & ops"),
    ("twilio", "Twilio", STATUSPAGE, "https://status.twilio.com/api/v2/summary.json", "https://status.twilio.com/", "Dev & ops"),
    ("openai", "OpenAI", STATUSPAGE, "https://status.openai.com/api/v2/summary.json", "https://status.openai.com/", "AI"),
    ("anthropic", "Claude", STATUSPAGE, "https://status.claude.com/api/v2/summary.json", "https://status.claude.com/", "AI"),
    ("apple", "Apple", "apple", "https://www.apple.com/support/systemstatus/data/system_status_en_US.js", "https://www.apple.com/support/systemstatus/", "Consumer"),
    ("shopify", "Shopify", STATUSPAGE, "https://www.shopifystatus.com/api/v2/summary.json", "https://www.shopifystatus.com/", "Consumer"),
    ("epic", "Epic Games", STATUSPAGE, "https://status.epicgames.com/api/v2/summary.json", "https://status.epicgames.com/", "Consumer"),
]
LONG_RUNNING_H = 72  # incidents older than this stay listed but no longer flash the alert


def _ts(v):
    """Epoch seconds/ms or a date string -> ISO 8601 UTC (or None)."""
    if v in (None, ""):
        return None
    try:
        n = float(v)
        return iso(datetime.fromtimestamp(n / 1000 if n > 1e11 else n, timezone.utc))
    except (TypeError, ValueError):
        return parse_dt(str(v))


def _cs_statuspage(url):
    d = get_json(url, timeout=20)
    out = []
    for i in d.get("incidents") or []:
        if i.get("status") in ("resolved", "postmortem"):
            continue
        imp = i.get("impact") or "none"
        out.append({"id": i.get("id"), "title": i.get("name") or "Incident",
                    "level": "major" if imp in ("major", "critical") else "minor" if imp == "minor" else "info",
                    "status": i.get("status"), "started": _ts(i.get("started_at") or i.get("created_at")),
                    "updated": _ts(i.get("updated_at")), "url": i.get("shortlink"),
                    "detail": _strip(((i.get("incident_updates") or [{}])[0]).get("body"))[:300],
                    "components": [c.get("name") for c in (i.get("components") or [])][:6]})
    bad = [c for c in d.get("components") or [] if c.get("status") in ("major_outage", "partial_outage", "degraded_performance")
           and not c.get("group")]
    for c in bad:
        if any(c.get("name") in x["components"] for x in out):
            continue
        out.append({"id": "c-" + str(c.get("id")), "title": "%s: %s" % (c.get("name"), c.get("status", "").replace("_", " ")),
                    "level": "major" if c.get("status") == "major_outage" else "minor", "status": c.get("status"),
                    "started": _ts(c.get("updated_at")), "updated": _ts(c.get("updated_at")), "url": None, "detail": "",
                    "components": [c.get("name")]})
    return out


def _cs_aws(url):
    raw = http_get(url, timeout=25)
    txt = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", "replace")
    out = []
    for e in json.loads(txt or "[]"):
        cur = [int(s.get("current") or 0) for s in (e.get("impacted_services") or {}).values()]
        st = max(cur) if cur else int(e.get("status") or 0)
        if st <= 0:
            continue
        log = sorted(e.get("event_log") or [], key=lambda x: x.get("timestamp") or 0)
        svcs = [s.get("service_name") for s in (e.get("impacted_services") or {}).values() if int(s.get("current") or 0) > 0]
        out.append({"id": e.get("arn") or e.get("service"), "title": "%s · %s%s" % (e.get("service_name") or e.get("service"),
                    e.get("summary") or "Service event", (" (" + e["region_name"] + ")") if e.get("region_name") else ""),
                    "level": "major" if st >= 3 else "minor" if st == 2 else "info", "status": str(st),
                    "started": _ts(e.get("date")), "updated": _ts(log[-1].get("timestamp")) if log else _ts(e.get("date")),
                    "url": None, "detail": _strip(log[-1].get("message"))[:300] if log else "", "components": svcs[:6]})
    return out


def _cs_google(url):
    out = []
    for i in get_json(url, timeout=25):
        if i.get("end"):
            continue
        imp = i.get("status_impact") or ""
        upd = i.get("most_recent_update") or {}
        out.append({"id": i.get("id"), "title": i.get("external_desc") or "Incident",
                    "level": "major" if imp == "SERVICE_OUTAGE" or i.get("severity") == "high" else
                             "minor" if imp == "SERVICE_DISRUPTION" else "info",
                    "status": upd.get("status") or imp, "started": _ts(i.get("begin")), "updated": _ts(i.get("modified")),
                    "url": ("https://status.cloud.google.com/" + i["uri"]) if "cloud.google" in url and i.get("uri") else None,
                    "detail": _strip(upd.get("text"))[:300],
                    "components": [p.get("title") for p in (i.get("affected_products") or [])][:6]})
    return out


def _cs_rss(url):
    """Azure: the feed only carries items while an incident is open."""
    raw = http_get(url, timeout=20).decode("utf8", "replace")
    out = []
    for m in re.finditer(r"<item\b.*?</item>", raw, re.S):
        blk = m.group(0)
        g = lambda n: _strip((re.search(r"<%s\b[^>]*>(.*?)</%s>" % (n, n), blk, re.S) or [None, ""])[1])  # noqa: E731
        title, when = g("title"), parse_dt(g("pubDate"))
        if not title or re.search(r"\b(resolved|mitigated|post incident review|\bPIR\b)", title, re.I):
            continue
        out.append({"id": g("guid") or title, "title": title,
                    "level": "minor" if re.search(r"degrad|intermittent|delay|latency|some customers", title, re.I) else "major",
                    "status": "active", "started": when, "updated": when, "url": g("link") or None,
                    "detail": g("description")[:300], "components": []})
    return out


def _cs_okta(url):
    raw = http_get(url, timeout=20).decode("utf8", "replace")
    out = []
    cut = now_utc() - timedelta(hours=48)
    for m in re.finditer(r"<entry\b.*?</entry>", raw, re.S):
        blk = m.group(0)
        g = lambda n: _strip((re.search(r"<%s\b[^>]*>(.*?)</%s>" % (n, n), blk, re.S) or [None, ""])[1])  # noqa: E731
        title, when = g("title"), parse_dt(g("updated"))
        if not title or title.lower().startswith("resolved") or not when or when < iso(cut):
            continue
        link = re.search(r'<link[^>]*href="([^"]+)"', blk)
        out.append({"id": g("id") or title, "title": title,
                    "level": "major" if re.search(r"service disruption|outage", title, re.I) else "minor",
                    "status": "active", "started": when, "updated": when, "url": link and link.group(1),
                    "detail": g("content")[:300], "components": []})
    return out


def _cs_slack(url):
    d = get_json(url, timeout=20)
    out = []
    for i in d.get("active_incidents") or []:
        typ = i.get("type") or "incident"
        out.append({"id": str(i.get("id")), "title": i.get("title") or "Incident",
                    "level": "major" if typ == "outage" else "minor" if typ == "incident" else "info",
                    "status": i.get("status"), "started": _ts(i.get("date_created")), "updated": _ts(i.get("date_updated")),
                    "url": i.get("url"), "detail": "", "components": (i.get("services") or [])[:6]})
    return out


def _cs_m365(url):
    out = []
    for p in get_json(url, timeout=20):
        st = p.get("Status") or ""
        if not st or st.lower() in ("operational", "serviceoperational", "resolved", "servicerestored"):
            continue
        out.append({"id": p.get("Id") or p.get("ServiceWorkloadName"), "title": "%s: %s" % (p.get("ServiceDisplayName"), p.get("Title") or st),
                    "level": "major" if re.search(r"interrupt|outage|down|unavailable", st, re.I) else "minor",
                    "status": st, "started": _ts(p.get("AuthoredDateTime")), "updated": _ts(p.get("LastUpdatedTime")),
                    "url": None, "detail": _strip(p.get("Message"))[:300], "components": [p.get("ServiceDisplayName")]})
    return out


def _cs_apple(url):
    """Apple System Status: only events that are still ongoing."""
    txt = http_get(url, timeout=20).decode("utf-8-sig", "replace").strip()
    if not txt.startswith("{"):
        txt = txt[txt.index("(") + 1:txt.rindex(")")]  # older JSONP wrapper
    out = []
    for sv in json.loads(txt).get("services") or []:
        for e in sv.get("events") or []:
            if (e.get("eventStatus") or "").lower() != "ongoing":
                continue
            typ = e.get("statusType") or "Issue"
            out.append({"id": "%s-%s" % (sv.get("serviceName"), e.get("messageId") or e.get("epochStartDate")),
                        "title": "%s: %s" % (sv.get("serviceName"), typ),
                        "level": "major" if typ.lower() == "outage" else "info" if "maint" in typ.lower() else "minor",
                        "status": e.get("eventStatus"), "started": _ts(e.get("epochStartDate")), "updated": _ts(e.get("epochStartDate")),
                        "url": None, "detail": _strip(e.get("message"))[:300], "components": [sv.get("serviceName")]})
    return out


def _cs_salesforce(url):
    """Salesforce Trust: active incidents across all instances."""
    out = []
    for i in get_json(url, timeout=20) or []:
        imp = [x for x in (i.get("IncidentImpacts") or []) if not x.get("endTime")] or (i.get("IncidentImpacts") or [])
        types = " ".join(str(x.get("type") or "") for x in imp).lower()
        ev = sorted(i.get("IncidentEvents") or [], key=lambda x: x.get("createdAt") or "")
        svc = ", ".join(i.get("serviceKeys") or []) or "Salesforce"
        inst = i.get("instanceKeys") or []
        out.append({"id": str(i.get("id")), "title": "%s incident%s" % (svc, (" on " + ", ".join(inst[:4]) + (" +%d" % (len(inst) - 4) if len(inst) > 4 else "")) if inst else ""),
                    "level": "major" if "major" in types or "outage" in types else "minor",
                    "status": "active", "started": _ts(i.get("createdAt")), "updated": _ts(i.get("updatedAt")),
                    "url": "https://status.salesforce.com/incidents/%s" % i.get("id"),
                    "detail": _strip(ev[-1].get("message") if ev else "")[:300], "components": (i.get("serviceKeys") or [])[:6]})
    return out


CS_KIND = {STATUSPAGE: _cs_statuspage, "aws": _cs_aws, "google": _cs_google, "rss": _cs_rss, "okta": _cs_okta,
           "slack": _cs_slack, "m365": _cs_m365, "apple": _cs_apple, "salesforce": _cs_salesforce}


def _cloud_services():
    svcs = list(CLOUD_SERVICES)
    # extra Statuspage providers from config.json: "status_pages": {"Name": "https://status.example.com"}
    try:
        extra = json.load(open(os.path.join(ROOT, "config.json"), encoding="utf-8")).get("status_pages") or {}
    except Exception:  # noqa: BLE001
        extra = {}
    for name, base in extra.items():
        base = str(base).rstrip("/")
        api = base if base.endswith(".json") else base + "/api/v2/summary.json"
        svcs.append((re.sub(r"\W+", "-", name.lower()), name, STATUSPAGE, api, base.split("/api/")[0] + "/", "Your status pages"))
    return svcs


def _cs_one(svc):
    sid, name, kind, api, page, group = svc
    try:
        inc = CS_KIND[kind](api)
        err = None
    except Exception as e:  # noqa: BLE001
        inc, err = [], str(e)[:160]
    now = now_utc()
    for i in inc:
        i["url"] = i.get("url") or page
        try:
            age_h = (now - datetime.strptime(i["started"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)).total_seconds() / 3600
        except Exception:  # noqa: BLE001
            age_h = 0
        i["longRunning"] = age_h > LONG_RUNNING_H
    # a months-long regional event shouldn't paint the provider red forever: it counts as degraded
    lv = ["minor" if i["level"] == "major" and i["longRunning"] else i["level"] for i in inc]
    state = "unknown" if err else "major" if "major" in lv else "minor" if "minor" in lv else "ok"
    inc.sort(key=lambda i: ({"major": 0, "minor": 1}.get(i["level"], 2), i.get("started") or ""))
    return {"id": sid, "name": name, "group": group, "page": page, "state": state, "incidents": inc[:12], "error": err}


def feed_cloudstatus():
    svcs = _cloud_services()
    with ThreadPoolExecutor(max_workers=12) as ex:
        res = list(ex.map(_cs_one, svcs))
    if all(r["error"] for r in res):
        raise IOError("no status page could be reached: %s" % res[0]["error"])
    alerts = [{"key": "%s|%s" % (r["id"], i["id"]), "service": r["name"], "title": i["title"], "started": i["started"],
               "url": i["url"], "level": i["level"]}
              for r in res for i in r["incidents"] if i["level"] == "major" and not i["longRunning"]]
    return {"services": res, "alerts": alerts, "checked": iso(now_utc()),
            "major": sum(r["state"] == "major" for r in res), "minor": sum(r["state"] == "minor" for r in res),
            "unknown": sum(r["state"] == "unknown" for r in res)}


# ---- C2 IOCs and malware URLs (keyless) ------------------------------------
# abuse.ch now needs an Auth-Key for ThreatFox, so the "threatfox" feed is built from C2IntelFeeds
# (public C2 server lists published on GitHub). The panel and layer ids stay the same.
C2INTEL = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/"


def _c2intel_family(desc):
    d = re.sub(r"^Possible\s+", "", (desc or "").strip(), flags=re.I)
    d = re.sub(r"\s*\(Unverified\)$", "", d, flags=re.I)
    d = re.sub(r"(\s+C2)?\s+IP$", "", d, flags=re.I)
    return {"Cobaltstrike": "Cobalt Strike"}.get(d, d) or "Unknown"


def feed_threatfox():
    def rows(path):
        txt = http_get(C2INTEL + path, timeout=40).decode("utf8", "replace")
        return [l.split(",") for l in txt.splitlines() if l and not l.startswith("#")]
    items, seen = [], set()
    for r in rows("IPPortC2s-30day.csv"):  # verified, with port
        ip = norm_ip(r[0]) if len(r) >= 3 else None
        if ip and ip not in seen:
            seen.add(ip)
            items.append({"ioc": "%s:%s" % (ip, r[1]), "type": "ip:port", "threat": "botnet_cc", "malware": _c2intel_family(r[-1]),
                          "confidence": 90, "firstSeen": None, "tags": ["verified"], "ip": ip})
    # unverified scanner hits: up to 450, shared fairly between tool families so the mix shows
    fam = {}
    for r in rows("unverified/IPC2s.csv"):
        ip = norm_ip(r[0]) if len(r) >= 2 else None
        if ip and ip not in seen:
            seen.add(ip)
            fam.setdefault(_c2intel_family(r[-1]), []).append(ip)
    queues = sorted(fam.items(), key=lambda kv: -len(kv[1]))
    while len(items) < 600 and any(q for _, q in queues):
        for f, q in queues:
            if q and len(items) < 600:
                ip = q.pop(0)
                items.append({"ioc": ip, "type": "ip", "threat": "botnet_cc", "malware": f, "confidence": 50,
                              "firstSeen": None, "tags": ["unverified"], "ip": ip})
    if not items:
        raise IOError("C2IntelFeeds returned no rows")
    return {"items": items, "families": Counter(x["malware"] for x in items).most_common(10)}


def feed_urlhaus():
    """URLhaus public list of online malware URLs (the plain-text export needs no key)."""
    # the online list first; if abuse.ch refuses it (it has answered 410 at times), the last-30-days list
    err = None
    for src in ("https://urlhaus.abuse.ch/downloads/text_online/", "https://urlhaus.abuse.ch/downloads/text_recent/"):
        try:
            txt = get_retry(http_get, src, tries=2, waits=(5,), timeout=40, headers={"Accept": "text/plain"}).decode("utf8", "replace")
            if "http" in txt:
                live = src.endswith("text_online/")
                break
        except Exception as e:  # noqa: BLE001
            err = e
    else:
        raise err or IOError("URLhaus returned an empty list")
    urls = [u.strip() for u in txt.split() if u.strip().startswith("http")]
    items = []
    for u in urls[:400]:
        host = (urllib.parse.urlsplit(u).hostname or "").lower()
        if not host:
            continue
        path = urllib.parse.urlsplit(u).path.lower()
        tags = [t for t, rx in (("elf", r"(\.sh|mips|arm\d?|x86|\.m68k|/i)$"), ("exe", r"\.(exe|msi|dll|scr)$"),
                                ("script", r"\.(ps1|vbs|js|hta|bat|lnk)$"), ("archive", r"\.(zip|rar|7z|iso)$"))
                if re.search(rx, path)]
        items.append({"url": defang(u), "host": host, "status": "online" if live else "listed", "threat": "malware_download",
                      "tags": tags, "added": None, "ip": norm_ip(host)})
    return {"items": items, "online": len(items) if live else 0, "total": len(urls), "list": "online" if live else "recent"}


def feed_porthist():
    """30-day DShield history for the currently most-targeted ports."""
    ent = CACHE.mem.get("attackers")
    ports = [p["port"] for p in (ent["data"].get("ports", []) if ent else [])][:6] or [22, 23, 80, 443, 445, 3389]
    end = now_utc().date() - timedelta(days=1)
    start = end - timedelta(days=29)

    def one(port):
        d = get_json("https://isc.sans.edu/api/porthistory/%d/%s/%s?json" % (port, start, end), timeout=40)
        rows = [v for k, v in sorted(((k, v) for k, v in d.items() if str(k).isdigit()), key=lambda kv: int(kv[0]))]
        return {"port": port, "name": PORT_NAMES.get(port, ""),
                "days": [{"date": r.get("date"), "records": int(r.get("records") or 0),
                          "sources": int(r.get("sources") or 0)} for r in rows]}
    with ThreadPoolExecutor(max_workers=6) as ex:
        out = [r for r in ex.map(lambda p: _safe(one, p), ports) if r]
    if not out:
        raise IOError("no port history available")
    return {"ports": out}


def _safe(fn, *a):
    try:
        return fn(*a)
    except Exception:  # noqa: BLE001
        return None


def feed_home():
    """Observer location for the radar scope: config override, else this machine's public-IP location."""
    if CONFIG.get("home_lat") and CONFIG.get("home_lon"):
        return {"lat": float(CONFIG["home_lat"]), "lon": float(CONFIG["home_lon"]),
                "name": CONFIG.get("home_name") or "Home", "source": "config"}
    r = get_json("http://ip-api.com/json/?fields=status,lat,lon,city,country")
    if r.get("status") != "success":
        raise IOError("could not determine location")
    return {"lat": r["lat"], "lon": r["lon"], "name": ", ".join(x for x in (r.get("city"), r.get("country")) if x),
            "source": "public IP"}


FEEDS = {
    # name: (fn, ttl seconds, ip-field-for-geo-enrichment or None, source label)
    "kev": (feed_kev, 3600, None, "CISA KEV"),
    "cves": (feed_cves, 1800, None, "NIST NVD"),
    "ransomware": (feed_ransomware, 900, None, "ransomware.live"),
    "c2": (feed_c2, 1800, "ip", "abuse.ch Feodo Tracker"),
    "attackers": (feed_attackers, 1800, "ip", "SANS ISC / DShield + Emerging Threats"),
    "tor": (feed_tor, 3600 * 6, "ip", "Tor Project"),
    "phishing": (feed_phishing, 1800, "ip", "OpenPhish community"),
    "outages": (feed_outages, 900, None, "IODA (Georgia Tech)"),
    "cables": (feed_cables, 86400, None, "TeleGeography Submarine Cable Map"),
    "news": (feed_news, 1200, None, "Security RSS"),
    "threatfox": (feed_threatfox, 3600, "ip", "C2IntelFeeds (C2 servers)"),
    "urlhaus": (feed_urlhaus, 1800, "ip", "abuse.ch URLhaus online list"),
    "porthist": (feed_porthist, 6 * 3600, None, "SANS ISC port history"),
    "home": (feed_home, 86400, None, "Observer location"),
    "epss": (feed_epss, 6 * 3600, None, "FIRST.org EPSS"),
    "cloudstatus": (feed_cloudstatus, 120, None, "Provider status pages"),
}


def build_feed(name):
    fn, ttl, ipfield, label = FEEDS[name]
    ent = CACHE.get(name, ttl, fn)
    data = ent["data"]
    if ipfield and isinstance(data, dict):
        data = dict(data)
        items = [dict(i) for i in data.get("items", [])]
        if name == "phishing":
            for it in items:
                it["ip"] = host_ip(it["host"])
        if name in ("threatfox", "urlhaus"):
            for it in items:
                if not it.get("ip") and it.get("host"):
                    it["ip"] = host_ip(it["host"])
        data["items"] = GEO.enrich(items, ipfield)
        if name == "attackers":
            data["compromised"] = GEO.enrich([dict(i) for i in data.get("compromised", [])])
    return {"feed": name, "source": label, "updated": ent["updated"], "stale": ent.get("stale", False),
            "data": data}


PORTS = {}


def status():
    out = {}
    for name, (_, ttl, _, label) in FEEDS.items():
        ent = CACHE.mem.get(name)
        out[name] = {"source": label, "updated": ent and ent["updated"], "ttl": ttl,
                     "error": CACHE.errors.get(name)}
    return {"feeds": out, "geo": {"pending": len(GEO.pending), "known": len(GEO.db), "error": GEO.last_error},
            "ports": PORTS, "server_time": iso(now_utc())}


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------
class Handler(SimpleHTTPRequestHandler):
    server_version = "KESTREL/1.0"

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=STATIC, **kw)

    def log_message(self, fmt, *args):
        if "/api/" in (args[0] if args else ""):
            return
        sys.stderr.write("[http] %s\n" % (fmt % args))

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        if not self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def _json(self, obj, code=200):
        body = json.dumps(obj, separators=(",", ":")).encode("utf8")
        gz = "gzip" in (self.headers.get("Accept-Encoding") or "") and len(body) > 2048
        if gz:
            body = gzip.compress(body, 5)
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        if gz:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path.startswith("/api/"):
            name = u.path[5:].strip("/")
            q = urllib.parse.parse_qs(u.query)
            try:
                if name == "status":
                    return self._json(status())
                if name in FEEDS:
                    return self._json(build_feed(name))
                return self._json({"error": "unknown endpoint"}, 404)
            except Exception as e:  # noqa: BLE001
                return self._json({"feed": name, "error": str(e)[:300]}, 502)
        if u.path == "/countries.json":
            with open(os.path.join(ROOT, "data", "countries.json"), "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        return super().do_GET()


class AnalyticsHandler(Handler):
    """Screen 2: same API and assets, but / serves the analytics page."""

    def do_GET(self):
        if urllib.parse.urlsplit(self.path).path in ("/", "/index.html"):
            self.path = "/analytics.html"
        return super().do_GET()


class MitreHandler(Handler):
    """Screen 3: same API and assets, but / serves the MITRE ATT&CK page."""

    def do_GET(self):
        if urllib.parse.urlsplit(self.path).path in ("/", "/index.html"):
            self.path = "/mitre.html"
        return super().do_GET()


def prewarm():
    order = ["kev", "ransomware", "c2", "attackers", "outages", "news", "cves", "phishing", "tor", "cables",
             "threatfox", "urlhaus", "porthist", "home", "epss", "cloudstatus"]
    for name in order:
        try:
            build_feed(name)
        except Exception:  # noqa: BLE001
            pass


def main():
    ap = argparse.ArgumentParser(description="KESTREL cyber threat observatory")
    ap.add_argument("--host", default=os.environ.get("KESTREL_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("KESTREL_PORT", "8787")))
    ap.add_argument("--analytics-port", type=int, default=int(os.environ.get("KESTREL_ANALYTICS_PORT", "8788")),
                    help="port for screen 2 (analytics); 0 disables it")
    ap.add_argument("--mitre-port", type=int, default=int(os.environ.get("KESTREL_MITRE_PORT", "8789")),
                    help="port for screen 3 (MITRE ATT&CK); 0 disables it")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    PORTS.update(face=args.port, analytics=args.analytics_port or None, mitre=args.mitre_port or None)
    shown = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host
    url = "http://%s:%d/" % (shown, args.port)
    if args.analytics_port:
        asrv = ThreadingHTTPServer((args.host, args.analytics_port), AnalyticsHandler)
        asrv.daemon_threads = True
        threading.Thread(target=asrv.serve_forever, daemon=True, name="analytics").start()
        url += "   analytics: http://%s:%d/" % (shown, args.analytics_port)
    if args.mitre_port:
        msrv = ThreadingHTTPServer((args.host, args.mitre_port), MitreHandler)
        msrv.daemon_threads = True
        threading.Thread(target=msrv.serve_forever, daemon=True, name="mitre").start()
        url += "   mitre: http://%s:%d/" % (shown, args.mitre_port)
    print(r"""
   _  _______ ___ _____ ___ ___ _
  | |/ / ____/ __|_   _| _ \ __| |      Cyber Threat Observatory
  | ' <| _|  \__ \ | | |   / _|| |__    %s
  |_|\_\___| |___/ |_| |_|_\___|____|   free public feeds, no API keys
""" % url)
    threading.Thread(target=prewarm, daemon=True).start()
    # stop.bat reads this to find the running server
    pid_file = os.path.join(ROOT, ".kestrel.pid")
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))

    def open_pages():
        webbrowser.open("http://%s:%d/" % (shown, args.port))
        if args.analytics_port:
            time.sleep(0.6)
            webbrowser.open("http://%s:%d/" % (shown, args.analytics_port))
    if not args.no_browser:
        threading.Timer(1.0, open_pages).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        GEO._save()
        try:
            os.remove(pid_file)
        except OSError:
            pass


if __name__ == "__main__":
    main()
