#!/usr/bin/env python3
"""SOCKS5 代理池网关守护进程 (Python 3.12+)
本地 SOCKS5:7929，自动抓取/测活/轮换上游代理
控制 API: http://127.0.0.1:7930
"""
import hashlib, json, os, re, signal, socket, ssl, struct, threading, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOCAL_HOST     = os.environ.get("PROXY_HOST", "127.0.0.1")
LOCAL_PORT     = int(os.environ.get("PROXY_PORT", "7929"))
CONTROL_PORT   = int(os.environ.get("CONTROL_PORT", "7930"))
TEST_TIMEOUT   = int(os.environ.get("TEST_TIMEOUT", "5"))
TEST_WORKERS   = int(os.environ.get("TEST_WORKERS", "150"))
FETCH_INTERVAL = int(os.environ.get("FETCH_INTERVAL", "86400"))   # 自动抓取间隔，默认1天
TEST_INTERVAL  = int(os.environ.get("TEST_INTERVAL",  "1800"))    # 仅测活间隔，默认30分钟
MIN_POOL_SIZE  = int(os.environ.get("MIN_POOL_SIZE",  "5"))       # 低于此数量立即重新抓取
MANUAL_REFRESH_ONLY = os.environ.get("MANUAL_REFRESH_ONLY", "0") == "1"   # 仅手动抓取
FILTER_RISK    = os.environ.get("FILTER_RISK", "1") == "1"   # 过滤高风控IP（proxy/hosting）
VERIFY_TLS     = os.environ.get("VERIFY_TLS", "1") == "1"    # 校验证书链，确保HTTPS可用
FAIL_THRESHOLD = int(os.environ.get("FAIL_THRESHOLD", "3"))   # 连续失败几次才换代理
GEO_BATCH      = 100
POOL_FILE      = Path(os.environ.get("POOL_FILE", "pool.json"))
OPENVPN_ENABLED = os.environ.get("OPENVPN_ENABLED", "1") == "1"
OPENVPN_POOL_FILE = Path(os.environ.get("OPENVPN_POOL_FILE", "openvpn.json"))
OPENVPN_CONFIG_DIR = Path(os.environ.get("OPENVPN_CONFIG_DIR", "openvpn-configs"))
OPENVPN_FETCH_TIMEOUT = int(os.environ.get("OPENVPN_FETCH_TIMEOUT", "20"))
OPENVPN_MAX_DOWNLOADS = int(os.environ.get("OPENVPN_MAX_DOWNLOADS", "30"))
OPENVPN_SOURCES = [
    u.strip() for u in os.environ.get(
        "OPENVPN_SOURCES", "https://publicvpnlist.com/country/usa/"
    ).split(",") if u.strip()
]

SOURCES = [
    "https://api.proxyscrape.com/v4/free-proxy-list/get"
    "?request=display_proxies&protocol=socks5&timeout=5000"
    "&country=all&ssl=all&anonymity=all&simplified=true",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
]
_PAT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})$")


# ── 抓取 ─────────────────────────────────────────────────────────────────────
def _fetch_source(url):
    ctx = ssl.create_default_context()
    for verify in (True, False):
        try:
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(url, context=ctx, timeout=15) as r:
                text = r.read().decode("utf-8", errors="ignore")
            return [l.strip() for l in text.splitlines() if _PAT.match(l.strip())]
        except Exception:
            continue
    return []

def fetch_raw():
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as ex:
        batches = list(ex.map(_fetch_source, SOURCES))
    seen, result = set(), []
    for batch in batches:
        for e in batch:
            if e not in seen:
                seen.add(e); result.append(e)
    return result


# ── OpenVPN 配置抓取 ───────────────────────────────────────────────────────────
_OVPN_DANGEROUS = (
    "script-security", "up", "down", "route-up", "route-pre-down",
    "ipchange", "client-connect", "client-disconnect", "learn-address",
    "auth-user-pass-verify", "tls-verify", "plugin",
)


def _safe_openvpn_id(url):
    p = urllib.parse.urlparse(url)
    raw = "{}-{}".format(p.netloc, p.path.strip("/") or "openvpn")
    base = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw).strip("-").lower() or "openvpn"
    digest = hashlib.sha1(url.encode()).hexdigest()[:8]
    return "{}-{}".format(base[:70], digest)


def _looks_like_ovpn(text):
    low = text[:2048].lower()
    if "<html" in low or "<!doctype html" in low:
        return False
    markers = ["client", "remote ", "dev tun", "dev tap", "proto ", "<ca>"]
    return sum(1 for m in markers if m in low) >= 3 and "remote " in low


def _parse_ovpn_metadata(cfg_id, url, text, path, source_meta=None):
    source_meta = source_meta or {}
    remote_host, remote_port = "", ""
    proto, dev = "", ""
    warnings = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        parts = s.split()
        key = parts[0].lower()
        if key == "remote" and len(parts) >= 3 and not remote_host:
            remote_host, remote_port = parts[1], parts[2]
        elif key == "proto" and len(parts) >= 2 and not proto:
            proto = parts[1]
        elif key == "dev" and len(parts) >= 2 and not dev:
            dev = parts[1]
        elif key in _OVPN_DANGEROUS:
            warnings.append("dangerous-directive:{}".format(key))
    return {
        "id": cfg_id,
        "url": url,
        "source": source_meta.get("source") or url,
        "country": source_meta.get("country") or source_meta.get("country_code") or "XX",
        "file": str(path),
        "remote_host": remote_host or source_meta.get("host", ""),
        "remote_port": remote_port or source_meta.get("port", ""),
        "proto": proto or (source_meta.get("proto", "unknown").lower()),
        "dev": dev or "unknown",
        "speed": source_meta.get("speed", ""),
        "latency": source_meta.get("latency", ""),
        "score": source_meta.get("score", ""),
        "checked_at": source_meta.get("checked", ""),
        "requires_auth": "auth-user-pass" in text,
        "warnings": sorted(set(warnings)),
        "fetched_at": time.time(),
    }


def _download_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "socks5-proxy-pool/1.0"})
    with urllib.request.urlopen(req, timeout=OPENVPN_FETCH_TIMEOUT) as r:
        raw = r.read(1024 * 1024)
    return raw.decode("utf-8", errors="ignore")


def _extract_openvpn_downloads(source_url, text):
    downloads = []
    seen = set()

    def add(url, attrs):
        if url in seen or len(downloads) >= OPENVPN_MAX_DOWNLOADS:
            return
        seen.add(url)
        downloads.append({
            "url": url,
            "source": source_url,
            "country": attrs.get("data-download-country") or attrs.get("data-country-name", ""),
            "country_code": attrs.get("data-download-code") or attrs.get("data-country", ""),
            "host": attrs.get("data-download-host") or attrs.get("data-download-ip") or attrs.get("data-host") or attrs.get("data-ip", ""),
            "port": attrs.get("data-download-port") or attrs.get("data-port", ""),
            "proto": attrs.get("data-download-proto") or attrs.get("data-proto", ""),
            "speed": attrs.get("data-download-speed") or attrs.get("data-speed", ""),
            "latency": attrs.get("data-download-latency") or attrs.get("data-latency", ""),
            "checked": attrs.get("data-download-checked") or attrs.get("data-checked-at", ""),
            "score": attrs.get("data-download-score", ""),
        })

    for m in re.finditer(r"<tr\b[^>]*data-id=[\"'](\d+)[\"'][^>]*>", text, re.I):
        tag = m.group(0)
        attrs = {k: v for k, v in re.findall(r"([a-zA-Z0-9_-]+)=[\"']([^\"']*)[\"']", tag)}
        dl = urllib.parse.urljoin(source_url, "/download/{}/".format(attrs.get("data-id") or m.group(1)))
        add(dl, attrs)

    for m in re.finditer(r"<a\b[^>]*href=[\"']([^\"']*/download/\d+/[^\"']*)[\"'][^>]*>", text, re.I):
        tag = m.group(0)
        attrs = {k: v for k, v in re.findall(r"([a-zA-Z0-9_-]+)=[\"']([^\"']*)[\"']", tag)}
        add(urllib.parse.urljoin(source_url, m.group(1)), attrs)

    return downloads


def _openvpn_source_items(source_url):
    text = _download_text(source_url)
    if _looks_like_ovpn(text):
        return [{"url": source_url, "text": text, "meta": {"source": source_url}}]
    downloads = _extract_openvpn_downloads(source_url, text)
    if not downloads:
        raise ValueError("no OpenVPN download links found")
    items = []
    for d in downloads:
        try:
            cfg_text = _download_text(d["url"])
            if not _looks_like_ovpn(cfg_text):
                raise ValueError("not an OpenVPN config")
            items.append({"url": d["url"], "text": cfg_text, "meta": d})
        except Exception as e:
            print("[openvpn] 下载失败 {}: {}".format(d["url"], e), flush=True)
    return items


def fetch_openvpn_configs():
    if not OPENVPN_ENABLED:
        return []
    OPENVPN_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for source_url in OPENVPN_SOURCES:
        try:
            items = _openvpn_source_items(source_url)
        except Exception as e:
            print("[openvpn] 抓取失败 {}: {}".format(source_url, e), flush=True)
            continue
        for item in items:
            cfg_id = _safe_openvpn_id(item["url"])
            path = OPENVPN_CONFIG_DIR / (cfg_id + ".ovpn")
            path.write_text(item["text"])
            results.append(_parse_ovpn_metadata(
                cfg_id, item["url"], item["text"], path, item.get("meta")))
        print("[openvpn] 来源 {} 抓取 {} 个配置".format(source_url, len(items)), flush=True)
    return results


# ── IP 地理定位 ───────────────────────────────────────────────────────────────
def geolocate(ips):
    out = {}
    fields = "query,countryCode,proxy,hosting" if FILTER_RISK else "query,countryCode"
    for i in range(0, len(ips), GEO_BATCH):
        chunk = ips[i:i + GEO_BATCH]
        data = json.dumps([{"query": ip} for ip in chunk]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=" + fields,
            data=data, headers={"Content-Type": "application/json"},
        )
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    for item in json.load(r):
                        risky = bool(item.get("proxy") or item.get("hosting"))
                        out[item["query"]] = {
                            "cc": item.get("countryCode") or "XX",
                            "risky": risky,
                        }
                break
            except Exception:
                time.sleep(15 * (attempt + 1))
        else:
            for ip in chunk:
                out[ip] = {"cc": "XX", "risky": False}
        time.sleep(1.5)
    return out


def test_socks5(host, port, timeout=TEST_TIMEOUT):
    t0 = time.monotonic()
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return None
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("8.8.8.8") + (53).to_bytes(2, "big"))
        if s.recv(10)[1] != 0:
            return None
        return (time.monotonic() - t0) * 1000
    except Exception:
        return None
    finally:
        if s:
            try: s.close()
            except: pass


def test_tls_via_socks5(host, port, timeout=TEST_TIMEOUT):
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return False
        target = b"example.com"
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) + target + (443).to_bytes(2, "big"))
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            return False
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(s, server_hostname="example.com") as tls:
            tls.settimeout(timeout)
            tls.do_handshake()
        return True
    except Exception:
        return False
    finally:
        if s:
            try: s.close()
            except: pass


# ── 抓取+测活 ─────────────────────────────────────────────────────────────────
def fetch_and_test():
    print("[pool] 抓取代理...", flush=True)
    raw = fetch_raw()
    print("[pool] {} 条，开始测活...".format(len(raw)), flush=True)
    geo = geolocate([e.split(":")[0] for e in raw])
    risky = {ip for ip, v in geo.items() if v["risky"]}
    if risky:
        print("[pool] 过滤高风控IP {} 个".format(len(risky)), flush=True)
    results = []
    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as ex:
        futs = {}
        for e in raw:
            ip, port = e.split(":", 1)
            if ip in risky:
                continue
            futs[ex.submit(test_socks5, ip, int(port))] = (ip, int(port))
        for fut in as_completed(futs):
            ip, port = futs[fut]
            latency = fut.result()
            if latency is None:
                continue
            if VERIFY_TLS and not test_tls_via_socks5(ip, port):
                continue
            results.append({
                "ip": ip, "port": port,
                "country": geo[ip]["cc"],
                "latency": round(latency),
            })
    results.sort(key=lambda x: (x["country"], x["latency"]))
    print("[pool] 可用 {} 条".format(len(results)), flush=True)
    return results


# ── 代理池 ────────────────────────────────────────────────────────────────────
class ProxyPool:
    def __init__(self):
        self._proxies = []
        self._current = None
        self._fail_count = 0
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if POOL_FILE.exists():
            try:
                data = json.loads(POOL_FILE.read_text())
                self._proxies = data.get("proxies", [])
                cur = data.get("current")
                self._current = next(
                    (p for p in self._proxies if p["ip"] == (cur or {}).get("ip")), None)
            except Exception:
                pass

    def save(self):
        POOL_FILE.write_text(json.dumps(
            {"proxies": self._proxies, "current": self._current,
             "updated_at": time.time()}, indent=2))

    def update(self, proxies):
        with self._lock:
            self._proxies = proxies
            if self._current not in proxies:
                self._current = proxies[0] if proxies else None
            self.save()

    def select(self, country=None, ip=None):
        with self._lock:
            candidates = self._proxies
            if country:
                candidates = [p for p in candidates if p["country"] == country]
            if ip:
                candidates = [p for p in candidates if p["ip"] == ip]
            if not candidates:
                return False
            self._current = candidates[0]
            self.save()
            return True

    def rotate(self):
        with self._lock:
            if not self._proxies:
                return None
            try:
                idx = self._proxies.index(self._current)
            except ValueError:
                idx = -1
            self._current = self._proxies[(idx + 1) % len(self._proxies)]
            return self._current

    def mark_success(self):
        with self._lock:
            self._fail_count = 0

    def mark_failure(self):
        with self._lock:
            self._fail_count += 1
            if self._fail_count >= FAIL_THRESHOLD:
                self._fail_count = 0
                if not self._proxies:
                    return
                try:
                    idx = self._proxies.index(self._current)
                except ValueError:
                    idx = -1
                self._current = self._proxies[(idx + 1) % len(self._proxies)]
                print("[pool] 代理失效，已切换到 {}:{}".format(
                    self._current["ip"], self._current["port"]), flush=True)

    @property
    def current(self):
        return self._current

    @property
    def proxies(self):
        return self._proxies

    def countries(self):
        cnt = {}
        for p in self._proxies:
            cnt[p["country"]] = cnt.get(p["country"], 0) + 1
        return dict(sorted(cnt.items(), key=lambda x: -x[1]))


class OpenVPNPool:
    def __init__(self):
        self._configs = []
        self._current = None
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if OPENVPN_POOL_FILE.exists():
            try:
                data = json.loads(OPENVPN_POOL_FILE.read_text())
                self._configs = data.get("configs", [])
                cur = data.get("current")
                self._current = next(
                    (c for c in self._configs if c["id"] == (cur or {}).get("id")), None)
            except Exception:
                pass

    def save(self):
        OPENVPN_POOL_FILE.write_text(json.dumps(
            {"configs": self._configs, "current": self._current,
             "updated_at": time.time()}, indent=2, ensure_ascii=False))

    def update(self, configs):
        with self._lock:
            cur_id = (self._current or {}).get("id")
            self._configs = configs
            self._current = next((c for c in configs if c["id"] == cur_id), None)
            if not self._current:
                self._current = configs[0] if configs else None
            self.save()

    def select(self, cfg_id=None):
        with self._lock:
            if not cfg_id:
                return False
            cur = next((c for c in self._configs if c["id"] == cfg_id), None)
            if not cur:
                return False
            self._current = cur
            self.save()
            return True

    def countries(self):
        cnt = {}
        for c in self._configs:
            cc = c.get("country") or "XX"
            cnt[cc] = cnt.get(cc, 0) + 1
        return dict(sorted(cnt.items(), key=lambda x: -x[1]))

    @property
    def current(self):
        return self._current

    @property
    def configs(self):
        return self._configs


pool = ProxyPool()
openvpn_pool = OpenVPNPool()


# ── 本地 SOCKS5 代理（链式转发到上游）────────────────────────────────────────
def _relay(a, b):
    def pipe(src, dst):
        try:
            while True:
                chunk = src.recv(4096)
                if not chunk:
                    break
                dst.sendall(chunk)
        except Exception:
            pass
        finally:
            for s in (src, dst):
                try: s.shutdown(socket.SHUT_RDWR)
                except: pass
    t = threading.Thread(target=pipe, args=(b, a), daemon=True)
    t.start()
    pipe(a, b)
    t.join()


def _socks5_upstream_connect(proxy, host, port):
    s = socket.create_connection((proxy["ip"], proxy["port"]), timeout=TEST_TIMEOUT)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise ConnectionError("upstream auth failed")
    host_b = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b
              + port.to_bytes(2, "big"))
    resp = s.recv(10)
    if resp[1] != 0:
        raise ConnectionError("upstream CONNECT failed: code={}".format(resp[1]))
    return s


def _handle_client(client):
    proxy = pool.current
    if not proxy:
        client.close()
        return
    try:
        client.recv(256)
        client.sendall(b"\x05\x00")
        req = client.recv(256)
        if len(req) < 7 or req[1] != 1:
            client.close()
            return
        atyp = req[3]
        if atyp == 1:
            host = socket.inet_ntoa(req[4:8])
            port = struct.unpack("!H", req[8:10])[0]
        elif atyp == 3:
            ln = req[4]
            host = req[5:5 + ln].decode()
            port = struct.unpack("!H", req[5 + ln:7 + ln])[0]
        else:
            client.close()
            return
        up = _socks5_upstream_connect(proxy, host, port)
        pool.mark_success()
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        _relay(client, up)
    except Exception:
        pool.mark_failure()
        client.close()


class _ProxyServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        family = socket.AF_INET6 if ":" in LOCAL_HOST else socket.AF_INET
        self._srv = socket.socket(family)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((LOCAL_HOST, LOCAL_PORT))
        self._srv.listen(256)

    def run(self):
        print("[proxy] listening on {}:{}".format(LOCAL_HOST, LOCAL_PORT), flush=True)
        while True:
            try:
                client, _ = self._srv.accept()
                threading.Thread(target=_handle_client, args=(client,), daemon=True).start()
            except Exception:
                pass


# ── HTTP 控制 API ─────────────────────────────────────────────────────────────
class _ControlHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/status":
            cur = pool.current
            self._json({
                "current": cur,
                "total": len(pool.proxies),
                "countries": pool.countries(),
                "local": "socks5://{}:{}".format(LOCAL_HOST, LOCAL_PORT),
                "openvpn": {
                    "enabled": OPENVPN_ENABLED,
                    "current": openvpn_pool.current,
                    "total": len(openvpn_pool.configs),
                },
            })
        elif p == "/proxies":
            cc = (self.path.split("country=")[-1] if "country=" in self.path else None)
            self._json([x for x in pool.proxies if not cc or x["country"] == cc])
        elif p == "/rotate":
            self._json({"current": pool.rotate()})
        elif p == "/refresh":
            threading.Thread(target=_do_refresh, daemon=True).start()
            self._json({"msg": "refresh started"})
        elif p == "/vpn/status":
            self._json({
                "enabled": OPENVPN_ENABLED,
                "current": openvpn_pool.current,
                "total": len(openvpn_pool.configs),
                "countries": openvpn_pool.countries(),
                "sources": OPENVPN_SOURCES,
                "config_dir": str(OPENVPN_CONFIG_DIR),
            })
        elif p == "/vpn/configs":
            self._json(openvpn_pool.configs)
        elif p == "/vpn/refresh":
            if not OPENVPN_ENABLED:
                self._json({"error": "openvpn disabled"}, 400)
            else:
                threading.Thread(target=_do_openvpn_refresh, daemon=True).start()
                self._json({"msg": "openvpn refresh started"})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(ln) or b"{}")
        if self.path == "/select":
            ok = pool.select(country=body.get("country"), ip=body.get("ip"))
            self._json({"ok": ok, "current": pool.current})
        elif self.path == "/vpn/select":
            ok = openvpn_pool.select(cfg_id=body.get("id"))
            self._json({"ok": ok, "current": openvpn_pool.current})
        else:
            self._json({"error": "not found"}, 404)


_last_fetch_time = 0.0
_last_test_time  = 0.0


def _do_refresh():
    global _last_fetch_time
    proxies = fetch_and_test()
    if proxies:
        pool.update(proxies)
        _last_fetch_time = time.monotonic()


def _do_openvpn_refresh():
    configs = fetch_openvpn_configs()
    if configs:
        openvpn_pool.update(configs)


def _test_only():
    global _last_test_time
    proxies = pool.proxies[:]
    if not proxies:
        return
    print("[pool] 测活 {} 条...".format(len(proxies)), flush=True)
    alive = []
    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as ex:
        futs = {ex.submit(test_socks5, p["ip"], p["port"]): p for p in proxies}
        for fut in as_completed(futs):
            p = futs[fut]
            latency = fut.result()
            if latency is not None:
                alive.append({**p, "latency": round(latency)})
    alive.sort(key=lambda x: (x["country"], x["latency"]))
    print("[pool] 存活 {} 条".format(len(alive)), flush=True)
    pool.update(alive)
    _last_test_time = time.monotonic()


def _refresh_loop():
    global _last_fetch_time
    if len(pool.proxies) < MIN_POOL_SIZE and not MANUAL_REFRESH_ONLY:
        _do_refresh()
    elif len(pool.proxies) >= MIN_POOL_SIZE:
        print("[pool] 已有缓存 {} 条，跳过启动抓取".format(len(pool.proxies)), flush=True)
        _last_fetch_time = time.monotonic()
    while True:
        time.sleep(FETCH_INTERVAL)
        if MANUAL_REFRESH_ONLY:
            continue
        _do_refresh()


def _test_loop():
    while True:
        time.sleep(TEST_INTERVAL)
        if len(pool.proxies) < MIN_POOL_SIZE and not MANUAL_REFRESH_ONLY:
            _do_refresh()
        elif _last_test_time < _last_fetch_time:
            _test_only()
        # else: 本次抓取周期内已测过，跳过


def main():
    _stop = threading.Event()

    def _shutdown(sig, _frame):
        print("\n[exit] signal {}".format(sig), flush=True)
        pool.save()
        _stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    _ProxyServer().start()

    ctrl = ThreadingHTTPServer(("127.0.0.1", CONTROL_PORT), _ControlHandler)
    threading.Thread(target=ctrl.serve_forever, daemon=True).start()
    print("[ctrl] http://127.0.0.1:{}".format(CONTROL_PORT), flush=True)

    if not MANUAL_REFRESH_ONLY:
        threading.Thread(target=_refresh_loop, daemon=True).start()
    threading.Thread(target=_test_loop, daemon=True).start()
    _stop.wait()


if __name__ == "__main__":
    main()
