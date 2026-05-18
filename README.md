# 🛡️ NetDefender — 网络安全攻防实验平台

> 网络安全课程设计项目，在虚拟化环境中模拟常见网络攻击并验证防御策略

## 项目概述

搭建隔离的虚拟网络环境，针对三种常见攻击场景进行攻防演练：
1. SYN Flood 拒绝服务攻击 → SYN Proxy + Cookies 防御
2. ARP 欺骗中间人攻击 → DHCP Snooping + 静态绑定防御
3. 端口扫描信息收集 → Snort IDS 检测 + 防火墙阻断

## 功能特性

- ✅ 基于 EVE-NG/GNS3 搭建隔离攻防实验环境
- ✅ 4 种攻击脚本（SYN Flood、ARP 欺骗、端口扫描、DHCP 耗尽）
- ✅ pfSense 防火墙规则配置
- ✅ Snort IDS 入侵检测规则
- ✅ Wireshark 流量分析 + Python 自动化解析
- ✅ 完整的攻防实验报告

## 目录结构

```
netdefender/
├── README.md
├── topology/
│   └── network_design.md         # 网络架构说明
├── attacks/
│   ├── syn_flood.py              # SYN Flood 攻击脚本
│   ├── arp_spoof.py              # ARP 欺骗脚本
│   ├── port_scan.py              # 端口扫描脚本
│   └── dhcp_starvation.py        # DHCP 耗尽攻击
├── defense/
│   ├── pfsense_rules.md          # pfSense 防火墙规则
│   ├── snort_rules.md            # Snort IDS 规则
│   ├── arp_static.py             # 静态 ARP 绑定脚本
│   └── dhcp_snooping.md          # DHCP Snooping 配置
├── analysis/
│   ├── wireshark_filters.md      # Wireshark 过滤器手册
│   ├── traffic_analyzer.py       # 流量分析脚本
│   └── attack_report.md          # 攻防实验报告
└── scripts/
    ├── setup_lab.sh              # 实验环境初始化
    └── generate_traffic.py       # 背景流量生成
```

## 实验环境要求

| 组件 | 用途 | 版本 |
|------|------|------|
| EVE-NG / GNS3 | 网络仿真平台 | Community / Pro |
| Kali Linux | 攻击机 | 2024.1+ |
| Ubuntu Server | 靶机 | 22.04 LTS |
| pfSense | 防火墙/路由器 | 2.7.x |
| Snort | 入侵检测系统 | 3.x |
| Wireshark | 流量分析 | 4.x |
| Python | 攻击脚本 | 3.10+ |
| Scapy | 网络包构造 | 2.5+ |

## ⚠️ 安全声明

本项目所有攻击脚本**仅限在隔离虚拟实验环境中使用**。
严禁在未授权的真实网络中使用，否则后果自负。

## 作者

网络工程 2023 级 | 广州应用科技学院
