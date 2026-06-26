#!/usr/bin/env python3
"""socks5-proxy-pool 交互式管理 CLI"""
import json, sys, urllib.request, urllib.error

CTRL = "http://127.0.0.1:7930"


def _get(path: str) -> dict:
    with urllib.request.urlopen(f"{CTRL}{path}", timeout=5) as r:
        return json.load(r)


def _post(path: str, data: dict) -> dict:
    body = json.dumps(data).encode()
    req = urllib.request.Request(f"{CTRL}{path}", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)


def _check_daemon() -> bool:
    try:
        _get("/status")
        return True
    except Exception:
        print("守护进程未运行，请先执行: python gateway.py")
        return False


def cmd_status() -> None:
    s = _get("/status")
    cur = s.get("current") or {}
    print(f"\n本地代理: {s['local']}")
    print(f"当前上游: {cur.get('ip','—')}:{cur.get('port','—')}  "
          f"[{cur.get('country','—')}] {cur.get('latency','—')}ms")
    print(f"可用总数: {s['total']}")
    print("\n按国家分布:")
    for cc, n in list(s["countries"].items())[:15]:
        print(f"  {cc:4s} {n:4d} 条")


def cmd_select() -> None:
    print("\n1.按国家选择  2.按IP选择  3.随机轮换")
    choice = input("请选择: ").strip()
    if choice == "1":
        s = _get("/status")
        countries = list(s["countries"].keys())
        for i, cc in enumerate(countries, 1):
            print(f"  {i:2d}. {cc}  ({s['countries'][cc]} 条)")
        idx = input("输入序号: ").strip()
        try:
            cc = countries[int(idx) - 1]
        except (ValueError, IndexError):
            print("无效选择")
            return
        res = _post("/select", {"country": cc})
        cur = res.get("current") or {}
        print(f"已切换到: {cur.get('ip')}:{cur.get('port')} [{cc}]")

    elif choice == "2":
        cc_input = input("输入国家代码 (留空=全部): ").strip().upper() or None
        path = f"/proxies?country={cc_input}" if cc_input else "/proxies"
        proxies = _get(path)
        if not proxies:
            print("无可用代理")
            return
        for i, p in enumerate(proxies[:30], 1):
            print(f"  {i:2d}. {p['ip']:16s}:{p['port']:5d}  [{p['country']}] {p['latency']}ms")
        idx = input("输入序号: ").strip()
        try:
            p = proxies[int(idx) - 1]
        except (ValueError, IndexError):
            print("无效选择")
            return
        res = _post("/select", {"ip": p["ip"]})
        cur = res.get("current") or {}
        print(f"已切换到: {cur.get('ip')}:{cur.get('port')}")

    elif choice == "3":
        cur = _get("/rotate").get("current") or {}
        print(f"已轮换到: {cur.get('ip')}:{cur.get('port')} [{cur.get('country')}]")


def cmd_refresh() -> None:
    _get("/refresh")
    print("已触发后台刷新（异步执行，约1-3分钟完成）")


def main() -> None:
    if not _check_daemon():
        sys.exit(1)

    cmds = {"1": cmd_status, "2": cmd_select, "3": cmd_refresh}
    while True:
        print("\n─────────────────────────────")
        print("1.查看状态    2.切换代理    3.刷新代理池    q.退出")
        c = input("请选择: ").strip().lower()
        if c == "q":
            break
        fn = cmds.get(c)
        if fn:
            try:
                fn()
            except urllib.error.URLError:
                print("连接守护进程失败")
        else:
            print("无效输入")


if __name__ == "__main__":
    main()
