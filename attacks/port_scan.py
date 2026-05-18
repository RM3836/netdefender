#!/usr/bin/env python3
"""
端口扫描脚本（信息收集）
============================================
⚠️  仅限在隔离虚拟实验环境中使用！
============================================

支持扫描方式：
1. TCP SYN 扫描（半开扫描，需 root 权限）
2. TCP Connect 扫描（完整三次握手）
3. UDP 扫描

用法:
  python port_scan.py --target 192.168.1.10
  python port_scan.py --target 192.168.1.10 --ports 1-1024 --method connect
"""
import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import IP, TCP, UDP, sr1, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

conf.verb = 0

# 常见端口服务映射
COMMON_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def parse_ports(port_str: str) -> list:
    """解析端口范围字符串，如 '1-1024' 或 '22,80,443'"""
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def tcp_connect_scan(target: str, port: int, timeout: float = 1.0) -> dict:
    """TCP Connect 扫描（完整三次握手）"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            return {"port": port, "state": "open", "service": service}
    except Exception:
        pass
    return {"port": port, "state": "closed", "service": ""}


def tcp_syn_scan(target: str, port: int, timeout: float = 1.0) -> dict:
    """TCP SYN 扫描（半开扫描，需 root 权限）"""
    if not HAS_SCAPY:
        return {"port": port, "state": "error", "service": "scapy not installed"}

    try:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout)

        if resp is None:
            return {"port": port, "state": "filtered", "service": ""}

        if resp.haslayer(TCP):
            tcp_flags = resp[TCP].flags
            if tcp_flags == 0x12:  # SYN-ACK
                # 发送 RST 关闭连接
                rst = IP(dst=target) / TCP(dport=port, flags="R")
                send(rst)
                service = COMMON_PORTS.get(port, "unknown")
                return {"port": port, "state": "open", "service": service}
            elif tcp_flags == 0x14:  # RST-ACK
                return {"port": port, "state": "closed", "service": ""}
    except Exception:
        pass
    return {"port": port, "state": "filtered", "service": ""}


def scan_target(target: str, ports: list, method: str = "connect",
                timeout: float = 1.0, threads: int = 50) -> list:
    """
    扫描目标端口
    Args:
        target: 目标 IP
        ports: 端口列表
        method: 扫描方法 (connect/syn)
        timeout: 超时时间
        threads: 并发线程数
    Returns:
        扫描结果列表
    """
    scan_fn = tcp_syn_scan if method == "syn" else tcp_connect_scan
    results = []

    print(f"[*] 扫描方法: TCP {method.upper()}")
    print(f"[*] 端口范围: {ports[0]}-{ports[-1]} ({len(ports)} 个)")
    print(f"[*] 并发线程: {threads}\n")

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_fn, target, port, timeout): port
            for port in ports
        }

        done_count = 0
        for future in as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                results.append(result)
                print(f"  [OPEN] {result['port']}/tcp  {result['service']}")
            done_count += 1
            if done_count % 100 == 0:
                print(f"  [..] 进度: {done_count}/{len(ports)}")

    elapsed = time.time() - start_time
    print(f"\n[*] 扫描完成: {len(results)} 个开放端口, 耗时 {elapsed:.1f}s")
    return sorted(results, key=lambda x: x["port"])


def main():
    parser = argparse.ArgumentParser(description="端口扫描（仅限实验环境）")
    parser.add_argument("--target", "-t", required=True, help="目标 IP")
    parser.add_argument("--ports", "-p", default="1-1024", help="端口范围 (默认 1-1024)")
    parser.add_argument("--method", "-m", choices=["connect", "syn"],
                        default="connect", help="扫描方法")
    parser.add_argument("--timeout", type=float, default=1.0, help="超时秒数")
    parser.add_argument("--threads", type=int, default=50, help="并发线程数")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════╗
║       端口扫描工具                  ║
║  ⚠️  仅限实验环境使用！            ║
╚══════════════════════════════════════╝
""")
    print(f"[*] 目标: {args.target}\n")

    ports = parse_ports(args.ports)
    results = scan_target(
        args.target, ports, args.method, args.timeout, args.threads
    )

    # 打印汇总
    if results:
        print(f"\n{'端口':<10} {'状态':<10} {'服务':<15}")
        print("-" * 35)
        for r in results:
            print(f"{r['port']:<10} {r['state']:<10} {r['service']:<15}")


if __name__ == "__main__":
    main()
