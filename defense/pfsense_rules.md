# pfSense 防火墙规则配置

## 1. 基本防火墙策略

### 默认策略
- WAN 口：默认拒绝所有入站（仅允许已建立连接的回程流量）
- LAN 口：默认允许所有出站

### 规则列表

| 优先级 | 方向 | 源 | 目标 | 端口 | 动作 | 说明 |
|--------|------|------|------|------|------|------|
| 1 | LAN | any | !LAN | 80,443 | ALLOW | 允许 Web 访问 |
| 2 | LAN | any | !LAN | 53 | ALLOW | 允许 DNS 查询 |
| 3 | LAN | Admin_Net | Server_Net | any | ALLOW | 管理员访问服务器 |
| 4 | LAN | Student_Net | Server_Net | any | BLOCK | 禁止学生访问服务器 |
| 5 | LAN | any | any | any | ALLOW | 其他流量放行 |

## 2. SYN Flood 防御

### 启用 SYN Proxy
```
# System → Advanced → Firewall & NAT
# 启用 SYN Proxy（代理三次握手，验证合法连接）

# 调整 TCP 参数
net.inet.tcp.syncookies=1          # 启用 SYN Cookies
net.inet.tcp.maxhalfopen=4096      # 半连接队列大小
net.inet.tcp.maxhalfopenretries=5  # 半连接重试次数
net.inet.tcp.keepidle=7200000      # Keepalive 空闲时间
```

### 速率限制规则
```
# 创建入站规则限制 SYN 速率
# Firewall → Rules → WAN

Action: Block
Interface: WAN
Protocol: TCP
Destination: LAN net
Destination Port: 80, 443
State Type: SYN Proxy
Max new connections / per second: 25
```

## 3. 端口扫描防御

### 启用暴力破解保护
```
# 启用 pfSense 内置的 SSH/HTTP 暴力破解防护
# System → Advanced → Admin Access
# SSH → Enable SSHGuard

# 配置 fail2ban 风格的自动封禁
# Firewall → Aliases → URL Table
# 创建恶意 IP 黑名单别名
```

### 端口敲门（Port Knocking）
```
# 隐藏管理端口，通过特定端口序列开放 SSH
# 1. 创建端口敲门规则序列
# 2. 只有按正确顺序访问 7000, 8000, 9000 后
#    才临时开放 22 端口 30 秒
```

## 4. 流量监控与告警

### 配置告警通知
```
# System → Advanced → Notifications
# 启用 Email 告警

# 告警条件：
# - 同一 IP 被防火墙阻断超过 10 次/分钟
# - 新的 DHCP 服务器出现在网络中
# - 异常的出站流量（C2 回连特征）
```

### 实时流量监控
```
# Diagnostics → pfTop
# 实时查看当前连接状态

# Diagnostics → Packet Capture
# 抓包分析可疑流量
```

## 5. VPN 加固

```
# 如果使用 OpenVPN 远程管理：
# - 使用 TLS 认证 + 证书认证
# - 限制 VPN 子网只允许访问管理网段
# - 启用 2FA（如 Google Authenticator）
# - 日志记录所有 VPN 连接
```
