#!/usr/bin/env python3
"""socks5-proxy-pool 交互式管理终端"""
import json, sys, urllib.request, urllib.error

CTRL = "http://127.0.0.1:7930"
SEP  = "─" * 48

def _get(path):
    try:
        with urllib.request.urlopen(CTRL + path, timeout=5) as r:
            return json.load(r)
    except urllib.error.URLError:
        print("守护进程未运行，请先: systemctl start socks5-gateway")
        sys.exit(1)

def _post(path, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(CTRL + path, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)

def show_status():
    s = _get("/status")
    cur = s.get("current") or {}
    print("\n" + SEP)
    print("  本地代理: {}".format(s.get("local", "")))
    if cur:
        print("  当前上游: {}:{}  [{}]  {}ms".format(
            cur.get("ip","—"), cur.get("port","—"),
            cur.get("country","—"), cur.get("latency","—")))
    else:
        print("  当前上游: 未选择（等待首次抓取完成）")
    print("  可用总数: {} 条 | {} 个国家".format(
        s.get("total", 0), len(s.get("countries", {}))))
    print(SEP)

def select_country():
    s = _get("/status")
    countries = list(s.get("countries", {}).items())
    if not countries:
        print("代理池为空，请等待刷新")
        return
    print()
    for i, (cc, n) in enumerate(countries, 1):
        print("  {:3d}. {}  ({} 条)".format(i, cc, n))
    print()
    idx = input("输入国家序号（回车取消）: ").strip()
    if not idx:
        return
    try:
        cc = countries[int(idx) - 1][0]
    except (ValueError, IndexError):
        print("无效输入")
        return
    res = _post("/select", {"country": cc})
    cur = res.get("current") or {}
    if cur:
        print("已切换 → {}:{}  [{}]  {}ms".format(
            cur.get("ip"), cur.get("port"), cur.get("country"), cur.get("latency")))
    else:
        print("切换失败")

def select_ip():
    cc = input("输入国家代码（留空=全部）: ").strip().upper() or None
    path = "/proxies?country={}".format(cc) if cc else "/proxies"
    proxies = _get(path)
    if not proxies:
        print("无可用代理")
        return
    print()
    for i, p in enumerate(proxies[:40], 1):
        print("  {:3d}. {:16s}:{:5d}  [{}]  {}ms".format(
            i, p["ip"], p["port"], p["country"], p["latency"]))
    if len(proxies) > 40:
        print("  ... 共 {} 条，显示前40".format(len(proxies)))
    print()
    idx = input("输入序号（回车取消）: ").strip()
    if not idx:
        return
    try:
        p = proxies[int(idx) - 1]
    except (ValueError, IndexError):
        print("无效输入")
        return
    res = _post("/select", {"ip": p["ip"]})
    cur = res.get("current") or {}
    if cur:
        print("已切换 → {}:{}  [{}]  {}ms".format(
            cur.get("ip"), cur.get("port"), cur.get("country"), cur.get("latency")))

def rotate():
    cur = _get("/rotate").get("current") or {}
    if cur:
        print("已轮换 → {}:{}  [{}]  {}ms".format(
            cur.get("ip"), cur.get("port"), cur.get("country"), cur.get("latency")))
    else:
        print("代理池为空")

def refresh():
    _get("/refresh")
    print("已触发后台刷新（异步执行，约1-3分钟）")

MENU = [
    ("按国家切换", select_country),
    ("按IP切换",   select_ip),
    ("轮换下一个", rotate),
    ("刷新代理池", refresh),
]

def main():
    while True:
        show_status()
        for i, (label, _) in enumerate(MENU, 1):
            print("  {}. {}".format(i, label))
        print("  0. 退出")
        print()
        c = input("请选择: ").strip()
        if c == "0" or c.lower() == "q":
            break
        try:
            MENU[int(c) - 1][1]()
        except (ValueError, IndexError):
            print("无效输入")

if __name__ == "__main__":
    main()
