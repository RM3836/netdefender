#!/usr/bin/env python3
"""
网络流量分析工具
读取 pcap 文件，自动检测异常流量模式

用法:
  python traffic_analyzer.py --pcap capture.pcapng
  python traffic_analyzer.py --pcap capture.pcapng --report report.json
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, TCP, UDP, IP, ARP, DNS
except ImportError:
    print("[!] 需要安装 scapy: pip install scapy")
    sys.exit(1)


class TrafficAnalyzer:
    """pcap 流量分析器"""

    def __init__(self, pcap_file: str):
        print(f"[*] 加载 pcap 文件: {pcap_file}")
        self.packets = rdpcap(pcap_file)
        print(f"[*] 共 {len(self.packets)} 个包\n")

        self.syn_count = Counter()       # SYN 包计数（按源 IP）
        self.arp_replies = defaultdict(list)  # ARP Reply 记录
        self.port_scan = defaultdict(set)     # 端口扫描记录
        self.connections = Counter()          # 连接计数
        self.protocols = Counter()            # 协议统计

    def analyze(self) -> dict:
        """执行完整分析"""
        results = {
            "total_packets": len(self.packets),
            "timestamp": datetime.now().isoformat(),
            "alerts": [],
            "statistics": {},
        }

        for pkt in self.packets:
            self._analyze_packet(pkt)

        # 检测 SYN Flood
        results["alerts"].extend(self._detect_syn_flood())

        # 检测 ARP 欺骗
        results["alerts"].extend(self._detect_arp_spoof())

        # 检测端口扫描
        results["alerts"].extend(self._detect_port_scan())

        # 统计信息
        results["statistics"] = {
            "protocols": dict(self.protocols.most_common(10)),
            "top_sources": dict(
                Counter({k: len(v) for k, v in self.port_scan.items()}).most_common(10)
            ),
        }

        return results

    def _analyze_packet(self, pkt):
        """分析单个包"""
        # 协议统计
        if pkt.haslayer(TCP):
            self.protocols["TCP"] += 1
        elif pkt.haslayer(UDP):
            self.protocols["UDP"] += 1
        elif pkt.haslayer(ARP):
            self.protocols["ARP"] += 1
        else:
            self.protocols["Other"] += 1

        # TCP SYN 统计
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            if pkt[TCP].flags == "S":  # SYN
                src = pkt[IP].src
                dst = pkt[IP].dst
                dport = pkt[TCP].dport
                self.syn_count[src] += 1
                self.port_scan[src].add(dport)
                self.connections[(src, dst)] += 1

        # ARP Reply 统计
        if pkt.haslayer(ARP):
            if pkt[ARP].op == 2:  # ARP Reply
                ip_addr = pkt[ARP].psrc
                mac_addr = pkt[ARP].hwsrc
                self.arp_replies[ip_addr].append(mac_addr)

    def _detect_syn_flood(self, threshold: int = 100) -> list:
        """检测 SYN Flood"""
        alerts = []
        for src_ip, count in self.syn_count.items():
            if count > threshold:
                alerts.append({
                    "type": "SYN_FLOOD",
                    "severity": "HIGH",
                    "source": src_ip,
                    "count": count,
                    "message": f"源 {src_ip} 发送 {count} 个 SYN 包（阈值 {threshold}）",
                })
        return alerts

    def _detect_arp_spoof(self) -> list:
        """检测 ARP 欺骗"""
        alerts = []
        for ip_addr, macs in self.arp_replies.items():
            unique_macs = set(macs)
            if len(unique_macs) > 1:
                alerts.append({
                    "type": "ARP_SPOOF",
                    "severity": "HIGH",
                    "target_ip": ip_addr,
                    "macs": list(unique_macs),
                    "message": f"IP {ip_addr} 对应 {len(unique_macs)} 个不同 MAC 地址",
                })
        return alerts

    def _detect_port_scan(self, threshold: int = 20) -> list:
        """检测端口扫描"""
        alerts = []
        for src_ip, ports in self.port_scan.items():
            if len(ports) > threshold:
                alerts.append({
                    "type": "PORT_SCAN",
                    "severity": "MEDIUM",
                    "source": src_ip,
                    "port_count": len(ports),
                    "sample_ports": sorted(list(ports))[:10],
                    "message": f"源 {src_ip} 扫描了 {len(ports)} 个不同端口",
                })
        return alerts


def main():
    parser = argparse.ArgumentParser(description="pcap 流量分析工具")
    parser.add_argument("--pcap", "-p", required=True, help="pcap 文件路径")
    parser.add_argument("--report", "-r", default=None, help="输出 JSON 报告路径")
    parser.add_argument("--threshold-syn", type=int, default=100, help="SYN Flood 阈值")
    parser.add_argument("--threshold-ports", type=int, default=20, help="端口扫描阈值")
    args = parser.parse_args()

    analyzer = TrafficAnalyzer(args.pcap)
    results = analyzer.analyze()

    # 打印告警
    print("=" * 60)
    print("分析结果")
    print("=" * 60)
    print(f"\n总包数: {results['total_packets']}")
    print(f"告警数: {len(results['alerts'])}\n")

    if results["alerts"]:
        print("--- 安全告警 ---")
        for alert in results["alerts"]:
            severity_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                alert["severity"], "⚪"
            )
            print(f"  {severity_icon} [{alert['severity']}] {alert['message']}")
    else:
        print("  [OK] 未检测到异常流量")

    # 打印统计
    print(f"\n--- 协议分布 ---")
    for proto, count in results["statistics"]["protocols"].items():
        pct = count / results["total_packets"] * 100
        print(f"  {proto}: {count} ({pct:.1f}%)")

    # 保存报告
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n[OK] 报告已保存: {args.report}")


if __name__ == "__main__":
    main()
