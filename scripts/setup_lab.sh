#!/bin/bash
# ==============================================
# 实验环境初始化脚本
# 在 EVE-NG/GNS3 中部署靶机环境
# ==============================================

set -e

echo "=========================================="
echo "  NetDefender 实验环境初始化"
echo "=========================================="

# 更新系统
echo "[1/6] 更新系统包..."
sudo apt update && sudo apt upgrade -y

# 安装基础工具
echo "[2/6] 安装基础工具..."
sudo apt install -y curl wget nmap net-tools tcpdump python3-pip

# 安装 Python 依赖
echo "[3/6] 安装 Python 依赖..."
pip3 install scapy requests

# 配置靶机 - Web 服务
echo "[4/6] 配置 Web 靶机 (Target-1)..."
if [ "$(hostname)" = "target-1" ]; then
    sudo apt install -y apache2
    sudo systemctl enable apache2
    echo "<h1>Target Web Server</h1>" | sudo tee /var/www/html/index.html
    echo "[OK] Apache2 已安装并启动"
fi

# 配置靶机 - FTP 服务
echo "[5/6] 配置 FTP 靶机 (Target-2)..."
if [ "$(hostname)" = "target-2" ]; then
    sudo apt install -y vsftpd
    sudo systemctl enable vsftpd
    echo "[OK] vsftpd 已安装并启动"
fi

# 配置靶机 - DNS 服务
echo "[6/6] 配置 DNS 靶机 (Target-3)..."
if [ "$(hostname)" = "target-3" ]; then
    sudo apt install -y bind9
    sudo systemctl enable named
    echo "[OK] BIND9 已安装并启动"
fi

# 配置防火墙允许实验流量
echo "[*] 配置 iptables 规则..."
sudo iptables -I INPUT -s 192.168.1.0/24 -j ACCEPT
sudo iptables -I OUTPUT -d 192.168.1.0/24 -j ACCEPT

echo ""
echo "=========================================="
echo "  环境初始化完成！"
echo "=========================================="
echo "靶机 IP: $(hostname -I | awk '{print $1}')"
echo "网关:    192.168.1.1"
echo ""
