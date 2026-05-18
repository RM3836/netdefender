# Wireshark 常用过滤器手册

## 基础过滤语法

| 过滤器 | 说明 | 示例 |
|--------|------|------|
| `ip.addr == X.X.X.X` | 按 IP 地址过滤 | `ip.addr == 192.168.1.10` |
| `ip.src == X.X.X.X` | 按源 IP 过滤 | `ip.src == 192.168.1.100` |
| `ip.dst == X.X.X.X` | 按目标 IP 过滤 | `ip.dst == 192.168.1.10` |
| `tcp.port == N` | 按 TCP 端口过滤 | `tcp.port == 80` |
| `udp.port == N` | 按 UDP 端口过滤 | `udp.port == 53` |
| `arp` | 只看 ARP 包 | `arp` |
| `tcp.flags.syn == 1` | SYN 包 | `tcp.flags.syn == 1` |

## 组合过滤

```
# 源 IP 且目标端口
ip.src == 192.168.1.100 && tcp.dstport == 80

# OR 条件
tcp.port == 80 || tcp.port == 443

# 排除某 IP
!(ip.addr == 192.168.1.1)

# 特定网段
ip.src >= 10.10.10.0 && ip.src <= 10.10.10.255
```

---

## 攻击检测过滤器

### SYN Flood 检测
```
# 找出所有 SYN 包（不含 SYN-ACK）
tcp.flags.syn == 1 && tcp.flags.ack == 0

# 按源 IP 统计 SYN 数量
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 192.168.1.10

# 统计命令（Wireshark 统计菜单）
# Statistics → Conversations → IPv4
# 按 Packets 排序，找出发包最多的源 IP
```

### ARP 欺骗检测
```
# 所有 ARP Reply 包
arp.opcode == 2

# 找出声称是网关的 ARP Reply
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.1.1

# 检查同一 IP 是否对应多个 MAC
# 步骤:
# 1. 过滤: arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.1.1
# 2. Statistics → Endpoints → Ethernet
# 3. 检查 192.168.1.1 是否出现多个 MAC 地址
```

### 端口扫描检测
```
# 找出向多个端口发送 SYN 的源 IP
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 192.168.1.10

# 检测 RST 包（端口关闭的响应）
tcp.flags.reset == 1 && ip.src == 192.168.1.10

# 统计目标端口分布
# Statistics → Conversations → TCP
# 按 Port 排序
```

### DHCP 攻击检测
```
# 所有 DHCP Discover
udp.port == 67 && dhcp.option.dhcp == 1

# 所有 DHCP Offer（检测伪造服务器）
udp.port == 68 && dhcp.option.dhcp == 2

# DHCP 完整流程
dhcp
```

---

## 实用统计命令

```
# 查看会话统计
Statistics → Conversations

# 查看协议分布
Statistics → Protocol Hierarchy

# 查看 IO 图表（流量趋势）
Statistics → IO Graphs

# 查看 HTTP 请求
Statistics → HTTP → Requests

# 导出特定流
右键 → Follow → TCP Stream
```

## 命令行过滤（tshark）

```bash
# 实时捕获并过滤
sudo tshark -i eth0 -f "host 192.168.1.100"

# 读取 pcap 文件并过滤
tshark -r capture.pcap -Y "tcp.flags.syn == 1"

# 统计 SYN 包数量
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" | wc -l

# 提取所有 HTTP URL
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```
