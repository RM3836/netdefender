#!/usr/bin/env python3
"""
静态 ARP 绑定脚本
用于防御 ARP 欺骗攻击

原理：在终端上静态绑定网关的 IP-MAC 映射
      防止攻击者伪造 ARP Reply 修改 ARP 缓存

用法:
  sudo python arp_static.py --gateway 192.168.1.1 --mac aa:bb:cc:dd:ee:ff
  sudo python arp_static.py --clear
  sudo python arp_static.py --show
"""
import argparse
import os
import platform
import subprocess
import sys


def run_cmd(cmd: str) -> tuple:
    """执行系统命令"""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def get_gateway_mac(gateway_ip: str) -> str:
    """获取网关当前的 MAC 地址"""
    system = platform.system()

    if system == "Linux":
        # 先 ping 一下确保 ARP 表有记录
        run_cmd(f"ping -c 1 -W 1 {gateway_ip}")
        code, out, _ = run_cmd(f"arp -n {gateway_ip}")
        if code == 0:
            parts = out.split()
            for i, part in enumerate(parts):
                if ":" in part and len(part) == 17:
                    return part
    elif system == "Windows":
        run_cmd(f"ping -n 1 -w 1000 {gateway_ip}")
        code, out, _ = run_cmd(f"arp -a {gateway_ip}")
        if code == 0:
            for line in out.splitlines():
                if gateway_ip in line:
                    parts = line.split()
                    for part in parts:
                        if "-" in part and len(part) == 17:
                            return part.replace("-", ":")

    return ""


def set_static_arp(gateway_ip: str, mac: str):
    """设置静态 ARP 绑定"""
    system = platform.system()

    if system == "Linux":
        # Linux: 使用 ip neigh 命令
        # 先删除现有条目
        run_cmd(f"ip neigh del {gateway_ip} dev $(ip route get {gateway_ip} | awk '{{print $5}}')")

        # 添加静态绑定
        iface_result = run_cmd(f"ip route get {gateway_ip}")
        iface = ""
        if iface_result[0] == 0:
            parts = iface_result[1].split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]

        if iface:
            cmd = f"ip neigh add {gateway_ip} lladdr {mac} dev {iface} nud permanent"
            code, out, err = run_cmd(cmd)
            if code == 0:
                print(f"[OK] 静态 ARP 绑定成功")
                print(f"     {gateway_ip} -> {mac} ({iface})")
            else:
                print(f"[FAIL] 绑定失败: {err}")
                print(f"       请使用 sudo 运行")
        else:
            print(f"[FAIL] 无法找到到达 {gateway_ip} 的网络接口")

    elif system == "Windows":
        # Windows: 使用 netsh 命令
        mac_win = mac.replace(":", "-")
        cmd = f"netsh interface ip add neighbors \"Ethernet\" {gateway_ip} {mac_win}"
        code, out, err = run_cmd(cmd)
        if code == 0:
            print(f"[OK] 静态 ARP 绑定成功: {gateway_ip} -> {mac}")
        else:
            print(f"[FAIL] 绑定失败: {err}")


def clear_static_arp(gateway_ip: str = None):
    """清除静态 ARP 绑定"""
    system = platform.system()

    if system == "Linux":
        if gateway_ip:
            run_cmd(f"ip neigh del {gateway_ip} dev $(ip route get {gateway_ip} | awk '{{print $5}}')")
            print(f"[OK] 已清除 {gateway_ip} 的 ARP 条目")
        else:
            print("[!] 请指定要清除的 IP 地址")

    elif system == "Windows":
        if gateway_ip:
            cmd = f"netsh interface ip delete neighbors \"Ethernet\" {gateway_ip}"
            run_cmd(cmd)
            print(f"[OK] 已清除 {gateway_ip} 的 ARP 条目")


def show_arp_table():
    """显示当前 ARP 表"""
    system = platform.system()
    if system == "Linux":
        code, out, _ = run_cmd("ip neigh show")
    else:
        code, out, _ = run_cmd("arp -a")

    if code == 0:
        print("\n当前 ARP 表:")
        print("=" * 50)
        print(out)


if __name__ == "__main__":
    if os.geteuid() != 0 and platform.system() == "Linux":
        print("[!] 需要 root 权限运行此脚本")
        print("    sudo python arp_static.py ...")

    parser = argparse.ArgumentParser(description="静态 ARP 绑定工具")
    parser.add_argument("--gateway", "-g", help="网关 IP 地址")
    parser.add_argument("--mac", "-m", help="网关 MAC 地址")
    parser.add_argument("--clear", action="store_true", help="清除静态绑定")
    parser.add_argument("--show", action="store_true", help="显示 ARP 表")
    parser.add_argument("--auto", action="store_true", help="自动获取网关 MAC 并绑定")
    args = parser.parse_args()

    if args.show:
        show_arp_table()
    elif args.clear:
        clear_static_arp(args.gateway)
    elif args.auto and args.gateway:
        mac = get_gateway_mac(args.gateway)
        if mac:
            print(f"[*] 检测到网关 MAC: {mac}")
            set_static_arp(args.gateway, mac)
        else:
            print(f"[!] 无法获取网关 MAC 地址")
    elif args.gateway and args.mac:
        set_static_arp(args.gateway, args.mac)
    else:
        parser.print_help()
