#!/bin/bash
set -e

REPO="https://github.com/youshang8520/socks5-proxy-pool"
INSTALL_DIR=/opt/socks5-proxy-pool
DATA_DIR=/var/lib/socks5-proxy-pool
SERVICE=socks5-gateway

echo "==> 检查依赖..."
PYTHON=$(command -v python3.12) || { echo "错误: 未找到 python3.12，请先安装"; exit 1; }

echo "==> 下载项目..."
if command -v git >/dev/null; then
    git clone --depth=1 "${REPO}" "${INSTALL_DIR}" 2>/dev/null \
        || (cd "${INSTALL_DIR}" && git pull)
else
    mkdir -p "${INSTALL_DIR}"
    curl -fsSL "${REPO}/archive/refs/heads/master.tar.gz" \
        | tar -xz -C "${INSTALL_DIR}" --strip-components=1
fi

echo "==> 创建数据目录..."
mkdir -p "${DATA_DIR}"

echo "==> 安装 systemd 服务..."
sed "s|/usr/bin/python3.12|${PYTHON}|g;
     s|/opt/socks5-proxy-pool|${INSTALL_DIR}|g;
     s|/var/lib/socks5-proxy-pool|${DATA_DIR}|g" \
    "${INSTALL_DIR}/socks5-gateway.service" \
    > /etc/systemd/system/${SERVICE}.service

systemctl daemon-reload
systemctl enable "${SERVICE}"
systemctl restart "${SERVICE}"

echo ""
echo "✓ 安装完成"
echo "  本地代理: socks5://127.0.0.1:7929"
echo "  查看状态: systemctl status ${SERVICE}"
echo "  管理CLI:  ${PYTHON} ${INSTALL_DIR}/cli.py"
echo "  查看日志: journalctl -u ${SERVICE} -f"
