#!/usr/bin/env python3
"""
背景流量生成器
在攻击期间生成正常业务流量，模拟真实环境

用法:
  python generate_traffic.py --target 192.168.1.10 --duration 300
"""
import argparse
import random
import time
import requests

# 模拟的 URL 路径
URL_PATHS = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/api/status",
    "/login",
    "/dashboard",
    "/images/logo.png",
    "/css/style.css",
    "/js/app.js",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/17.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
]


def generate_http_traffic(target: str, port: int = 80, duration: int = 300):
    """生成 HTTP 背景流量"""
    base_url = f"http://{target}:{port}"
    start_time = time.time()
    request_count = 0

    print(f"[*] 目标: {base_url}")
    print(f"[*] 持续: {duration} 秒")
    print(f"[*] 按 Ctrl+C 停止\n")

    try:
        while time.time() - start_time < duration:
            path = random.choice(URL_PATHS)
            ua = random.choice(USER_AGENTS)
            headers = {"User-Agent": ua}

            try:
                resp = requests.get(
                    f"{base_url}{path}",
                    headers=headers,
                    timeout=2,
                )
                request_count += 1
                print(f"  [{request_count}] GET {path} -> {resp.status_code}")
            except requests.exceptions.RequestException:
                pass

            # 随机间隔 0.5-3 秒
            time.sleep(random.uniform(0.5, 3.0))

    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start_time
    print(f"\n[*] 完成: {request_count} 个请求, 耗时 {elapsed:.1f}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="背景流量生成器")
    parser.add_argument("--target", "-t", required=True, help="目标 IP")
    parser.add_argument("--port", "-p", type=int, default=80, help="目标端口")
    parser.add_argument("--duration", "-d", type=int, default=300, help="持续秒数")
    args = parser.parse_args()

    generate_http_traffic(args.target, args.port, args.duration)
