# socks5-proxy-pool

自动抓取/测活公开 SOCKS5 代理，暴露本地代理网关，支持按国家/IP 切换。另支持抓取 OpenVPN `.ovpn` 配置并在 CLI 菜单中管理。

## 安装 / 更新

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/youshang8520/socks5-proxy-pool/master/install.sh)
```

安装完成后：
- 本地代理自动启动：`socks5://127.0.0.1:7929`
- 管理 CLI：`python3 /opt/socks5-proxy-pool/cli.py`
- 查看日志：`journalctl -u socks5-gateway -f`

守护进程会：
1. 从公开来源并联抓取 SOCKS5 代理
2. 过滤高风控 IP，并做 SOCKS5 连通与 HTTPS TLS 校验
3. 暴露本地 SOCKS5 代理 `127.0.0.1:7929`
4. 有缓存时启动跳过抓取，手动或定时刷新代理池
5. 支持通过菜单手动抓取 OpenVPN `.ovpn` 配置

## 管理

```bash
python3 /opt/socks5-proxy-pool/cli.py
```

功能：
- 查看当前代理状态和按国家分布
- 按国家/IP 手动选择上游代理
- 轮换下一个代理
- 手动抓取 SOCKS5 代理池
- 查看 / 抓取 / 选择 OpenVPN 配置

> OpenVPN 抓取只负责下载和保存 `.ovpn` 配置，不会自动连接 OpenVPN，也不会修改系统路由。

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PROXY_HOST` | `127.0.0.1` | 本地代理监听地址，默认仅本机可用 |
| `PROXY_PORT` | `7929` | 本地代理端口 |
| `CONTROL_PORT` | `7930` | 控制 API 端口 |
| `FETCH_INTERVAL` | `86400` | 自动抓取间隔（秒） |
| `TEST_INTERVAL` | `1800` | 仅测活间隔（秒） |
| `MIN_POOL_SIZE` | `5` | 低于此数量时重新抓取 |
| `MANUAL_REFRESH_ONLY` | `0` | `1` 表示只允许手动抓取 |
| `TEST_TIMEOUT` | `5` | 连通测试超时（秒） |
| `TEST_WORKERS` | `150` | 并发测试数 |
| `FAIL_THRESHOLD` | `3` | 连续失败几次后切换代理 |
| `FILTER_RISK` | `1` | 过滤 ip-api 标记的 proxy/hosting IP |
| `VERIFY_TLS` | `1` | 校验 HTTPS TLS 证书链 |
| `OPENVPN_ENABLED` | `1` | 启用 OpenVPN 配置抓取 API/菜单 |
| `OPENVPN_SOURCES` | `https://publicvpnlist.com/country/usa/` | OpenVPN 来源，支持国家列表页或直接下载链接，多个 URL 用英文逗号分隔 |
| `OPENVPN_POOL_FILE` | `openvpn.json` | OpenVPN 元数据文件 |
| `OPENVPN_CONFIG_DIR` | `openvpn-configs` | `.ovpn` 配置保存目录 |

## 控制 API

SOCKS5：

```text
GET  /status              # 当前状态
GET  /proxies?country=US  # 指定国家代理列表
GET  /rotate              # 轮换下一个代理
GET  /refresh             # 触发后台刷新
POST /select  {"country":"US"} | {"ip":"1.2.3.4"}  # 选择代理
```

OpenVPN：

```text
GET  /vpn/status          # OpenVPN 抓取状态
GET  /vpn/configs         # 已抓取的 .ovpn 配置列表
GET  /vpn/refresh         # 手动抓取 OpenVPN 配置
POST /vpn/select {"id":"配置ID"}  # 选择当前 OpenVPN 配置
```

## OpenVPN 说明

当前 OpenVPN 功能只做三件事：

1. 从 `OPENVPN_SOURCES` 抓取国家列表页或直接下载链接
2. 对 `publicvpnlist.com/country/xxx/` 这类页面，解析每行 `data-id`、`data-ip`、`data-port`、`data-proto`，再下载 `/download/{id}/` 对应 `.ovpn`
3. 校验是否像 OpenVPN 配置，避免把 HTML 错误页存进去
4. 保存配置文件和元数据，供 CLI 查看/选择

不会自动运行 `openvpn`。如果后续需要一键连接/断开，需要额外配置 OpenVPN 客户端或 systemd 服务，因为连接 OpenVPN 通常需要 root 权限、TUN 设备和路由变更。
