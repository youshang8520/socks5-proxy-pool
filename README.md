# socks5-proxy-pool

自动抓取/测活公开 SOCKS5 代理，暴露本地代理网关，支持按国家/IP 切换。

## 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/youshang8520/socks5-proxy-pool/master/install.sh)
```

安装完成后：
- 本地代理自动启动：`socks5://127.0.0.1:7929`
- 管理 CLI：`python3 /opt/socks5-proxy-pool/cli.py`
- 查看日志：`journalctl -u socks5-gateway -f`



守护进程会：
1. 从3个来源并联抓取 SOCKS5 代理
2. 并发测活（默认150线程）并按国家分组
3. 暴露本地 SOCKS5 代理 `127.0.0.1:7929`
4. 每30分钟自动刷新代理池

## 管理

```bash
python cli.py   # 交互式管理终端
```

功能：
- 查看当前代理状态和按国家分布
- 按国家/IP 手动选择上游代理
- 随机轮换
- 触发手动刷新

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PROXY_PORT` | `7929` | 本地代理端口 |
| `CONTROL_PORT` | `7930` | 控制 API 端口 |
| `FETCH_INTERVAL` | `1800` | 刷新间隔（秒） |
| `TEST_TIMEOUT` | `5` | 连通测试超时（秒） |
| `TEST_WORKERS` | `150` | 并发测试数 |

## 控制 API

```
GET  /status              # 当前状态
GET  /proxies?country=US  # 指定国家代理列表
GET  /rotate              # 随机轮换
GET  /refresh             # 触发后台刷新
POST /select  {"country":"US"} | {"ip":"1.2.3.4"}  # 选择代理
```
