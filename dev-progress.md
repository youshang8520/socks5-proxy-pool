# dev-progress.md

## 2026-06-27

### 当前任务：增加 OpenVPN 抓取/菜单管理
- 用户确认需要“抓 OpenVPN”，不是把 OpenVPN 当作 SOCKS5 来源。
- 目标是先实现 OpenVPN 配置抓取、保存、状态查看、菜单触发；不自动连接 OpenVPN，避免修改系统路由或要求守护进程提权。
- 同时处理此前安全要求：本地 SOCKS5 默认只监听 `127.0.0.1`，避免 `0.0.0.0:7929` 对外开放。
- 已发现需同步修复：`gateway.py` 当前引用 `FAIL_THRESHOLD`，但常量缺失，会在代理失败切换路径触发 `NameError`。

### 设计决策
- SOCKS5 代理池继续使用 `pool.json`，OpenVPN 配置单独保存到 `openvpn.json` 和 `openvpn-configs/`。
- OpenVPN 抓取默认关闭，通过 `OPENVPN_ENABLED=1` 开启。
- OpenVPN 来源通过 `OPENVPN_SOURCES` 逗号分隔配置，默认 `https://publicvpnlist.com/country/usa/`；抓取器会解析国家页里每个 `tr data-id/data-ip/data-port/data-proto`，拼出 `/download/{id}/` 下载 `.ovpn`。
- CLI 增加 OpenVPN 菜单项，调用本地控制 API。
- 不在当前阶段实现 OpenVPN connect/disconnect。

### 已执行
- 修改 `gateway.py`：
  - `PROXY_HOST` 默认改为 `127.0.0.1`。
  - 恢复/新增 `FAIL_THRESHOLD` 常量。
  - 新增 OpenVPN 配置抓取、校验、解析、保存逻辑。
  - 新增 `OpenVPNPool`，OpenVPN 元数据独立于 SOCKS5 `pool.json`。
  - 新增控制 API：`/vpn/status`、`/vpn/configs`、`/vpn/refresh`、`/vpn/select`。
- 修改 `cli.py`：增加 OpenVPN 状态、手动抓取、选择配置菜单。
- 修改 `install.sh` 与 `socks5-gateway.service`：创建 OpenVPN 配置目录，配置 OpenVPN 数据路径与默认来源。
- 修改 `README.md`：更新监听地址、安全说明、OpenVPN 菜单/API/环境变量说明。

### 验证
- 已运行 `python -m py_compile gateway.py cli.py`，通过。
- 已运行 `bash -n install.sh`，通过。
- 已运行 OpenVPN 本地样例解析测试：可从 `tr data-id/data-ip/data-port/data-proto` 生成 `https://publicvpnlist.com/download/{id}/`。
- 已对真实 `https://publicvpnlist.com/country/usa/` 页面做列表解析检查，得到 18 个下载链接。

### 待执行
- 提交并推送。
