# DHCP Snooping 配置

## 原理

DHCP Snooping 是交换机的安全功能，作用：
1. 区分信任端口和非信任端口
2. 丢弃来自非信任端口的 DHCP Offer/ACK 报文
3. 构建 DHCP Snooping 绑定表（IP-MAC-VLAN-端口映射）
4. 防止 DHCP 耗尽攻击和伪造 DHCP 服务器

## Cisco 交换机配置

```
! 1. 全局启用 DHCP Snooping
ip dhcp snooping

! 2. 在指定 VLAN 上启用
ip dhcp snooping vlan 10,20,30,50

! 3. 配置信任端口（连接 DHCP 服务器或上联口）
interface g0/1
 description Trunk-to-Core-SW
 ip dhcp snooping trust

! 4. 配置非信任端口的速率限制（防耗尽攻击）
interface range f0/1-24
 description Access-Ports
 ip dhcp snooping limit rate 10

! 5. 可选：启用 MAC 验证
ip dhcp snooping verify mac-address
```

## 验证命令

```
show ip dhcp snooping              # 查看 Snooping 全局状态
show ip dhcp snooping binding      # 查看绑定表
show ip dhcp snooping statistics   # 查看统计数据
show ip dhcp snooping interface    # 查看接口状态
```

## 绑定表示例

```
MacAddress          IpAddress        Lease(sec)  Type           VLAN  Interface
------------------  ---------------  ----------  -------------  ----  ---------
00:1A:2B:3C:4D:5E   10.10.10.11      28800       dhcp-snooping  10    Fa0/1
00:2B:3C:4D:5E:6F   10.10.10.12      28800       dhcp-snooping  10    Fa0/2
AA:BB:CC:DD:EE:FF   10.10.50.101     14400       dhcp-snooping  50    Fa0/10
```

## 测试验证

### 测试 1：伪造 DHCP 服务器
```
攻击机（Kali）启动伪造 DHCP 服务器:
  sudo dnsmasq --interface=eth0 --dhcp-range=192.168.1.200,192.168.1.250,12h

预期结果: 交换机丢弃来自非信任端口的 DHCP Offer
实际结果: ✅ 伪造 DHCP 报文被丢弃，日志记录告警
```

### 测试 2：DHCP 耗尽攻击
```
攻击机（Kali）执行 DHCP 耗尽:
  python dhcp_starvation.py --interface eth0 --count 500

预期结果: 速率限制生效，每端口最多 10 个 DHCP 请求/秒
实际结果: ✅ 超过速率的请求被丢弃，地址池未耗尽
```

### 测试 3：合法终端获取 IP
```
新终端接入，请求 DHCP 地址:
  dhclient -v eth0

预期结果: 正常获取 IP 地址
实际结果: ✅ 192.168.1.x 分配成功，绑定表新增条目
```
