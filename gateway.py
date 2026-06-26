#!/usr/bin/env python3
"""SOCKS5 代理池网关守护进程 (Python 3.12+)
本地 SOCKS5:7929，自动抓取/测活/轮换上游代理
控制 API: http://127.0.0.1:7930
"""
import json, os, re, signal, socket, ssl, struct, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOCAL_HOST     = os.environ.get("PROXY_HOST", "0.0.0.0")
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
GEO_BATCH      = 100
POOL_FILE      = Path(os.environ.get("POOL_FILE", "pool.json"))

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


pool = ProxyPool()


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
            })
        elif p == "/proxies":
            cc = (self.path.split("country=")[-1] if "country=" in self.path else None)
            self._json([x for x in pool.proxies if not cc or x["country"] == cc])
        elif p == "/rotate":
            self._json({"current": pool.rotate()})
        elif p == "/refresh":
            threading.Thread(target=_do_refresh, daemon=True).start()
            self._json({"msg": "refresh started"})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(ln) or b"{}")
        if self.path == "/select":
            ok = pool.select(country=body.get("country"), ip=body.get("ip"))
            self._json({"ok": ok, "current": pool.current})
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
