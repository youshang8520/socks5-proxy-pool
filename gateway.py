#!/usr/bin/env python3
"""SOCKS5 代理池网关守护进程
本地 SOCKS5:7929，自动抓取/测活/轮换上游代理
控制 API: http://127.0.0.1:7930
"""
from __future__ import annotations
import json, os, re, socket, ssl, struct, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ── 配置 ────────────────────────────────────────────────────────────────────
LOCAL_HOST     = os.environ.get("PROXY_HOST", "0.0.0.0")
LOCAL_PORT     = int(os.environ.get("PROXY_PORT", "7929"))
CONTROL_PORT   = int(os.environ.get("CONTROL_PORT", "7930"))
TEST_TIMEOUT   = int(os.environ.get("TEST_TIMEOUT", "5"))
TEST_WORKERS   = int(os.environ.get("TEST_WORKERS", "150"))
FETCH_INTERVAL = int(os.environ.get("FETCH_INTERVAL", "1800"))   # 秒
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
def _fetch_source(url: str) -> list[str]:
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

def fetch_raw() -> list[str]:
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as ex:
        batches = list(ex.map(_fetch_source, SOURCES))
    seen: set[str] = set()
    result: list[str] = []
    for batch in batches:
        for e in batch:
            if e not in seen:
                seen.add(e); result.append(e)
    return result

# ── IP 地理定位 ───────────────────────────────────────────────────────────────
def geolocate(ips: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for i in range(0, len(ips), GEO_BATCH):
        chunk = ips[i:i + GEO_BATCH]
        data = json.dumps([{"query": ip} for ip in chunk]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=query,countryCode",
            data=data, headers={"Content-Type": "application/json"},
        )
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    for item in json.load(r):
                        out[item["query"]] = item.get("countryCode") or "XX"
                break
            except Exception:
                time.sleep(15 * (attempt + 1))
        else:
            for ip in chunk:
                out[ip] = "XX"
        time.sleep(1.5)
    return out

# ── SOCKS5 连通测试 ───────────────────────────────────────────────────────────
def test_socks5(host: str, port: int, timeout: int = TEST_TIMEOUT) -> float | None:
    """返回延迟毫秒，失败返回 None"""
    t0 = time.monotonic()
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
        try: s.close()
        except: pass

# ── 代理池 ────────────────────────────────────────────────────────────────────
class ProxyPool:
    def __init__(self) -> None:
        self._proxies: list[dict] = []
        self._current: dict | None = None
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if POOL_FILE.exists():
            try:
                data = json.loads(POOL_FILE.read_text())
                self._proxies = data.get("proxies", [])
                cur = data.get("current")
                self._current = next((p for p in self._proxies
                                      if p["ip"] == (cur or {}).get("ip")), None)
            except Exception:
                pass

    def save(self) -> None:
        POOL_FILE.write_text(json.dumps(
            {"proxies": self._proxies, "current": self._current,
             "updated_at": time.time()}, indent=2))

    def update(self, proxies: list[dict]) -> None:
        with self._lock:
            self._proxies = proxies
            if self._current not in proxies:
                self._current = proxies[0] if proxies else None
            self.save()

    def select(self, *, country: str | None = None, ip: str | None = None) -> bool:
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

    def rotate(self) -> dict | None:
        with self._lock:
            if not self._proxies:
                return None
            try:
                idx = self._proxies.index(self._current)
            except ValueError:
                idx = -1
            self._current = self._proxies[(idx + 1) % len(self._proxies)]
            return self._current

    @property
    def current(self) -> dict | None:
        return self._current

    @property
    def proxies(self) -> list[dict]:
        return self._proxies

    def countries(self) -> dict[str, int]:
        cnt: dict[str, int] = {}
        for p in self._proxies:
            cnt[p["country"]] = cnt.get(p["country"], 0) + 1
        return dict(sorted(cnt.items(), key=lambda x: -x[1]))


pool = ProxyPool()

# ── 本地 SOCKS5 代理（链式转发到上游）────────────────────────────────────────
def _relay(a: socket.socket, b: socket.socket) -> None:
    def pipe(src, dst):
        try:
            while chunk := src.recv(4096):
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


def _socks5_upstream_connect(proxy: dict, host: str, port: int) -> socket.socket:
    s = socket.create_connection((proxy["ip"], proxy["port"]), timeout=TEST_TIMEOUT)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise ConnectionError("upstream auth failed")
    host_b = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b
              + port.to_bytes(2, "big"))
    resp = s.recv(10)
    if resp[1] != 0:
        raise ConnectionError(f"upstream CONNECT failed: code={resp[1]}")
    return s


def _handle_client(client: socket.socket) -> None:
    proxy = pool.current
    if not proxy:
        client.close()
        return
    try:
        # SOCKS5 handshake with local client
        client.recv(256)
        client.sendall(b"\x05\x00")  # no-auth

        req = client.recv(256)
        if len(req) < 7 or req[1] != 1:  # only CONNECT
            client.close()
            return
        atyp = req[3]
        if atyp == 1:    # IPv4
            host = socket.inet_ntoa(req[4:8])
            port = struct.unpack("!H", req[8:10])[0]
        elif atyp == 3:  # domain
            ln = req[4]
            host = req[5:5 + ln].decode()
            port = struct.unpack("!H", req[5 + ln:7 + ln])[0]
        else:
            client.close()
            return

        up = _socks5_upstream_connect(proxy, host, port)
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        _relay(client, up)
    except Exception:
        pool.rotate()
        client.close()


class _ProxyServer(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self._srv = socket.socket(socket.AF_INET6 if ":" in LOCAL_HOST else socket.AF_INET)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((LOCAL_HOST, LOCAL_PORT))
        self._srv.listen(256)

    def run(self) -> None:
        print(f"[proxy] listening on {LOCAL_HOST}:{LOCAL_PORT}", flush=True)
        while True:
            try:
                client, _ = self._srv.accept()
                threading.Thread(target=_handle_client, args=(client,),
                                 daemon=True).start()
            except Exception:
                pass


# ── HTTP 控制 API ─────────────────────────────────────────────────────────────
class _ControlHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, data: object, code: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        p = self.path.split("?")[0]
        if p == "/status":
            cur = pool.current
            self._json({
                "current": cur,
                "total": len(pool.proxies),
                "countries": pool.countries(),
                "local": f"socks5://{LOCAL_HOST}:{LOCAL_PORT}",
            })
        elif p == "/proxies":
            cc = (self.path.split("country=")[-1] if "country=" in self.path else None)
            lst = [x for x in pool.proxies if not cc or x["country"] == cc]
            self._json(lst)
        elif p == "/rotate":
            self._json({"current": pool.rotate()})
        elif p == "/refresh":
            threading.Thread(target=_do_refresh, daemon=True).start()
            self._json({"msg": "refresh started"})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        ln = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(ln) or b"{}")
        if self.path == "/select":
            ok = pool.select(country=body.get("country"), ip=body.get("ip"))
            self._json({"ok": ok, "current": pool.current})
        else:
            self._json({"error": "not found"}, 404)


def _do_refresh() -> None:
    proxies = fetch_and_test()
    if proxies:
        pool.update(proxies)


# ── 后台定时刷新 ──────────────────────────────────────────────────────────────
def _refresh_loop() -> None:
    _do_refresh()                       # 启动时立即抓一次
    while True:
        time.sleep(FETCH_INTERVAL)
        _do_refresh()


# ── 主入口 ────────────────────────────────────────────────────────────────────
def main() -> None:
    _ProxyServer().start()

    ctrl = ThreadingHTTPServer(("127.0.0.1", CONTROL_PORT), _ControlHandler)
    threading.Thread(target=ctrl.serve_forever, daemon=True).start()
    print(f"[ctrl] http://127.0.0.1:{CONTROL_PORT}", flush=True)

    threading.Thread(target=_refresh_loop, daemon=True).start()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n[exit]", flush=True)


if __name__ == "__main__":
    main()

    print("[pool] 抓取代理...", flush=True)
    raw = fetch_raw()
    print(f"[pool] {len(raw)} 条，开始测活...", flush=True)

    geo = geolocate([e.split(":")[0] for e in raw])

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as ex:
        futs = {ex.submit(test_socks5, ip, int(port)): (ip, int(port))
                for e in raw for ip, port in [e.split(":", 1)]}
        for fut in as_completed(futs):
            ip, port = futs[fut]
            latency = fut.result()
            if latency is not None:
                results.append({
                    "ip": ip, "port": port,
                    "country": geo.get(ip, "XX"),
                    "latency": round(latency),
                })
    results.sort(key=lambda x: (x["country"], x["latency"]))
    print(f"[pool] 可用 {len(results)} 条", flush=True)
    return results
