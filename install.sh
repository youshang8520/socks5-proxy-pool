#!/bin/bash
set -e

REPO="https://github.com/youshang8520/socks5-proxy-pool"
INSTALL_DIR=/opt/socks5-proxy-pool
DATA_DIR=/var/lib/socks5-proxy-pool
SERVICE=socks5-gateway

echo "==> 检查依赖..."
if ! command -v python3.12 >/dev/null 2>&1; then
    echo "安装 Python 3.12..."
    if command -v dnf >/dev/null; then
        dnf install -y python3.12
    elif command -v yum >/dev/null; then
        yum install -y python312 2>/dev/null || {
            yum install -y gcc openssl-devel bzip2-devel libffi-devel zlib-devel
            curl -fsSL https://www.python.org/ftp/python/3.12.7/Python-3.12.7.tgz | tar xz -C /tmp
            (cd /tmp/Python-3.12.7 && ./configure --prefix=/usr/local --enable-optimizations && make -j$(nproc) && make altinstall)
        }
    elif command -v apt-get >/dev/null; then
        apt-get install -y software-properties-common
        add-apt-repository -y ppa:deadsnakes/ppa
        apt-get update -y && apt-get install -y python3.12
    fi
fi
PYTHON=$(command -v python3.12 || command -v python3)

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
sed "s|/opt/socks5-proxy-pool|${INSTALL_DIR}|g;
     s|/var/lib/socks5-proxy-pool|${DATA_DIR}|g" \
    "${INSTALL_DIR}/socks5-gateway.service" \
    > /etc/systemd/system/${SERVICE}.service

systemctl daemon-reload
systemctl enable --now "${SERVICE}"

echo ""
echo "✓ 安装完成"
echo "  本地代理: socks5://127.0.0.1:7929"
echo "  查看状态: systemctl status ${SERVICE}"
echo "  管理CLI:  python3 ${INSTALL_DIR}/cli.py"
echo "  查看日志: journalctl -u ${SERVICE} -f"
