#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志分析脚本：提取指定用户的所有调用IP，并按路由统计次数
支持两种日志格式:
  1. ERR行: [ERR] ... | <request_id> | user <uid> | ...
  2. INFO行: [INFO] ... | <request_id> | ... userId=<uid>, ...
对应GIN行: [GIN] ... | relay | <request_id> | <status> | <duration> | <ip> | <method> <route>

用法: python analyze_user_logs.py <log_file> <user_id>
示例: python analyze_user_logs.py "C:/Users/60201/Downloads/oneapi-20260412024740.log" 647
"""

import sys
import re
import os
from collections import defaultdict


def analyze_user_logs(log_file: str, user_id: str):
    if not os.path.exists(log_file):
        print(f"[ERROR] 文件不存在: {log_file}")
        sys.exit(1)

    file_size = os.path.getsize(log_file)
    print(f"[INFO] 日志文件: {log_file}")
    print(f"[INFO] 文件大小: {file_size / 1024 / 1024:.2f} MB")
    print(f"[INFO] 目标用户: user {user_id}")
    print(f"[INFO] 开始分析...\n")

    # ---------------------------------------------------------------
    # 匹配模式
    # ---------------------------------------------------------------

    # 格式1: [ERR/WARN/INFO] ... | <request_id> | user 647 | 消息
    # 示例: [ERR] 2026/04/14 - 05:05:38 | 202604132105383804637228268d9d668OMnjHC | user 647 | No available...
    pat_user_pipe = re.compile(
        r'\|\s*([A-Za-z0-9]+)\s*\|\s*user\s+' + re.escape(user_id) + r'\b'
    )

    # 格式2: [INFO] ... | <request_id> | ... userId=<uid>, ...
    # 示例: [INFO] 2026/04/14 - 09:52:18 | 202604140152152598723408268d9d6XUMTZZaw | record consume log: userId=647, ...
    pat_user_id_eq = re.compile(
        r'\|\s*([A-Za-z0-9]+)\s*\|.*?userId=' + re.escape(user_id) + r'\b'
    )

    # GIN行: [GIN] ... | relay | <request_id> | <status> | <duration> | <ip> | <METHOD> <route>
    # 示例: [GIN] 2026/04/14 - 09:52:18 | relay | 202604140152152598... | 200 | 3.566641877s | 103.248.154.14 | POST /v1/messages?beta=true
    pat_gin = re.compile(
        r'\[GIN\][^|]+\|[^|]+\|\s*([A-Za-z0-9]+)\s*\|\s*(\d+)\s*\|[^|]+\|\s*([\d.:a-fA-F]+)\s*\|\s*((?:POST|GET|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+\S+)'
    )

    # ---------------------------------------------------------------
    # 第一遍：收集 user_id 对应的所有 request_id
    # ---------------------------------------------------------------
    print("[PASS 1] 扫描所有行，收集 user 对应的 request_id ...")
    user_request_ids = set()
    line_count = 0

    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line_count += 1
            if line_count % 500_000 == 0:
                print(f"  已扫描 {line_count:,} 行，当前找到 {len(user_request_ids)} 个请求ID...")

            # 先快速检测是否包含目标user_id，减少正则开销
            if user_id not in line:
                continue

            m = pat_user_pipe.search(line)
            if m:
                user_request_ids.add(m.group(1).strip())
                continue

            m = pat_user_id_eq.search(line)
            if m:
                user_request_ids.add(m.group(1).strip())

    print(f"[PASS 1] 完成，共扫描 {line_count:,} 行，找到 {len(user_request_ids)} 个唯一请求ID\n")

    if not user_request_ids:
        print(f"[WARN] 未找到 user {user_id} 的任何请求记录，请检查用户ID是否正确。")
        return

    # ---------------------------------------------------------------
    # 第二遍：从GIN行中匹配 request_id，提取IP和路由
    # ---------------------------------------------------------------
    print("[PASS 2] 扫描GIN行，提取IP和路由...")

    ip_route_stats: dict[tuple, int] = defaultdict(int)
    ip_stats: dict[str, int] = defaultdict(int)
    route_stats: dict[str, int] = defaultdict(int)

    line_count = 0
    matched_count = 0
    unmatched_req_ids = set(user_request_ids)  # 用于追踪未命中的request_id

    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line_count += 1
            if line_count % 500_000 == 0:
                print(f"  已扫描 {line_count:,} 行，已匹配 {matched_count} 条...")

            if '[GIN]' not in line:
                continue

            m = pat_gin.search(line)
            if not m:
                continue

            req_id = m.group(1).strip()
            if req_id not in user_request_ids:
                continue

            status = m.group(2).strip()
            ip = m.group(3).strip()
            method_route = m.group(4).strip()

            # 标准化路由（去掉query string中的参数，但保留路径）
            route_clean = method_route.split('?')[0] if '?' in method_route else method_route

            ip_route_stats[(ip, route_clean)] += 1
            ip_stats[ip] += 1
            route_stats[route_clean] += 1
            matched_count += 1
            unmatched_req_ids.discard(req_id)

    print(f"[PASS 2] 完成，共扫描 {line_count:,} 行，匹配到 {matched_count} 条GIN记录\n")

    if matched_count == 0:
        print("[WARN] 未找到任何匹配的GIN请求记录。")
        sample_ids = list(user_request_ids)[:5]
        print(f"       样本 request_id: {sample_ids}")
        return

    # ---------------------------------------------------------------
    # 输出结果
    # ---------------------------------------------------------------
    separator = "=" * 80
    sep2 = "-" * 60

    lines_out = []
    lines_out.append(separator)
    lines_out.append(f"  用户 {user_id} 调用统计报告")
    lines_out.append(f"  日志文件: {log_file}")
    lines_out.append(f"  唯一请求ID数: {len(user_request_ids)}  |  匹配GIN记录数: {matched_count}")
    if unmatched_req_ids:
        lines_out.append(f"  ⚠ 有 {len(unmatched_req_ids)} 个request_id未在GIN日志中找到对应IP记录")
    lines_out.append(separator)

    lines_out.append(f"\n【1】IP地址统计（共 {len(ip_stats)} 个不同IP，按调用次数降序）")
    lines_out.append(sep2)
    for ip, count in sorted(ip_stats.items(), key=lambda x: -x[1]):
        lines_out.append(f"  {ip:<45} 请求次数: {count:>6}")

    lines_out.append(f"\n【2】路由统计（共 {len(route_stats)} 个不同路由，按调用次数降序）")
    lines_out.append(sep2)
    for route, count in sorted(route_stats.items(), key=lambda x: -x[1]):
        lines_out.append(f"  {route:<55} 请求次数: {count:>6}")

    lines_out.append(f"\n【3】IP + 路由 详细统计（共 {len(ip_route_stats)} 个组合，按次数降序）")
    lines_out.append(sep2)
    lines_out.append(f"  {'IP地址':<45} {'路由':<45} {'次数':>6}")
    lines_out.append(f"  {'-'*44} {'-'*44} {'------':>6}")
    for (ip, route), count in sorted(ip_route_stats.items(), key=lambda x: -x[1]):
        lines_out.append(f"  {ip:<45} {route:<45} {count:>6}")

    output_text = "\n".join(lines_out)
    print(output_text)

    # 保存到文件
    output_file = f"user_{user_id}_ip_stats.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(output_text + "\n")

    print(f"\n[INFO] 统计结果已保存至: {os.path.abspath(output_file)}")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        default_log = r"C:\Users\60201\Downloads\oneapi-20260412024740.log"
        default_user = "647"
        print(f"[INFO] 未提供参数，使用默认值: log={default_log}, user_id={default_user}")
        analyze_user_logs(default_log, default_user)
    else:
        analyze_user_logs(sys.argv[1], sys.argv[2])
