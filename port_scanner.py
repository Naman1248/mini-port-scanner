#!/usr/bin/env python3
"""
Mini Port Scanner (TCP Connect Scan)
Author: Naman Patil (your repo)
License: MIT

Purpose:
- Fast, concurrent TCP connect() scanner.
- Parses flexible port ranges (e.g., "22,80,443,8000-8100").
- Maps well-known services and optionally grabs simple banners.
- Outputs to console, CSV, or JSON.

Legal Note:
Use only on hosts you own or have explicit authorization to test.
"""

import argparse
import concurrent.futures as cf
import json
import socket
import sys
import time
from typing import Iterable, List, Tuple, Set

# -------- Port parsing --------
def parse_ports(spec: str) -> List[int]:
    """
    Parse a port specification like "22,80,443,8000-8100"
    into a sorted, unique list of ints within [1, 65535].
    """
    ports: Set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a = a.strip(); b = b.strip()
            if not (a.isdigit() and b.isdigit()):
                raise ValueError(f"Invalid range: {part}")
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            for p in range(max(1, start), min(65535, end) + 1):
                ports.add(p)
        else:
            if not part.isdigit():
                raise ValueError(f"Invalid port: {part}")
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
            else:
                raise ValueError(f"Port out of range: {p}")
    return sorted(ports)

# -------- Scanner core --------
def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"

def try_banner(sock: socket.socket, port: int, timeout: float) -> str:
    """
    Very lightweight banner grab:
    - For common HTTP-ish ports, send a minimal HTTP request.
    - Otherwise, try to recv() a small banner without sending.
    """
    sock.settimeout(timeout)
    try:
        # Minimal probing for HTTP-like ports
        if port in {80, 8080, 8000, 8008, 8888}:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        # Try to read any immediate data (many services won’t send)
        data = sock.recv(256)
        if not data:
            return ""
        # Clean to single line printable
        text = data.decode(errors="ignore").replace("\r", " ").replace("\n", " ").strip()
        return " ".join(text.split())[:200]
    except Exception:
        return ""

def scan_one(target: str, port: int, timeout: float, banner: bool) -> Tuple[int, bool, str]:
    """
    Returns (port, is_open, banner_text)
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                btxt = try_banner(sock, port, timeout) if banner else ""
                return (port, True, btxt)
            else:
                return (port, False, "")
        except Exception:
            return (port, False, "")

# -------- Output helpers --------
def print_table(results: List[Tuple[int, bool, str]]):
    opens = [(p, b) for (p, ok, b) in results if ok]
    if not opens:
        print("\nNo open TCP ports found.")
        return
    print("\nOpen TCP Ports:")
    print("-" * 72)
    print(f"{'PORT':<8}{'SERVICE':<18}{'BANNER/NOTE'}")
    print("-" * 72)
    for port, banner in opens:
        svc = get_service_name(port)
        note = banner if banner else ""
        print(f"{port:<8}{svc:<18}{note}")
    print("-" * 72)
    print(f"Total open: {len(opens)}\n")

def save_csv(path: str, results: List[Tuple[int, bool, str]]):
    opens = [(p, b) for (p, ok, b) in results if ok]
    with open(path, "w", encoding="utf-8") as f:
        f.write("port,service,banner\n")
        for port, banner in opens:
            svc = get_service_name(port)
            b = banner.replace('"', "'")
            f.write(f'{port},{svc},"{b}"\n')

def save_json(path: str, results: List[Tuple[int, bool, str]]):
    opens = []
    for (port, ok, banner) in results:
        if ok:
            opens.append({
                "port": port,
                "service": get_service_name(port),
                "banner": banner
            })
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"target_results": opens}, f, indent=2)

# -------- CLI --------
def main():
    ap = argparse.ArgumentParser(description="Mini TCP Port Scanner")
    ap.add_argument("--target", required=True, help="Target IPv4/hostname (e.g., 127.0.0.1 or 192.168.80.1)")
    ap.add_argument("--ports", default="1-1024",
                    help='Ports spec (e.g., "22,80,443,8000-8100"). Default: 1-1024')
    ap.add_argument("--timeout", type=float, default=1.0, help="Socket timeout seconds (default 1.0)")
    ap.add_argument("--workers", type=int, default=200, help="Max concurrent workers (default 200)")
    ap.add_argument("--banner", action="store_true", help="Attempt simple banner grabbing on open ports")
    ap.add_argument("--out", choices=["csv", "json"], help="Optional output format")
    ap.add_argument("--outfile", help="Output file path (used with --out)")
    args = ap.parse_args()

    # Resolve target early to fail fast on typos
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror as e:
        print(f"[-] DNS resolution failed for {args.target}: {e}")
        sys.exit(2)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[-] {e}")
        sys.exit(2)

    if args.out and not args.outfile:
        print("[-] Provide --outfile when using --out csv/json")
        sys.exit(2)

    print(f"[+] Scanning target {args.target} ({target_ip})")
    print(f"[+] Ports: {len(ports)} specified")
    print(f"[+] Timeout: {args.timeout}s | Workers: {args.workers} | Banner: {bool(args.banner)}")
    t0 = time.time()

    results: List[Tuple[int, bool, str]] = []
    # Use ThreadPoolExecutor for concurrent connect() scans
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(scan_one, target_ip, p, args.timeout, args.banner) for p in ports]
        done = 0
        total = len(futures)
        for fut in cf.as_completed(futures):
            port, is_open, banner = fut.result()
            results.append((port, is_open, banner))
            done += 1
            # Lightweight progress indicator
            if done % max(1, total // 20) == 0 or done == total:
                pct = int(done * 100 / total)
                print(f"\r[=] Progress: {done}/{total} ({pct}%)", end="", flush=True)
    print()  # newline after progress

    # Sort results by port
    results.sort(key=lambda x: x[0])

    # Human-readable
    print_table(results)

    # Optional save
    if args.out == "csv":
        save_csv(args.outfile, results)
        print(f"[+] CSV written to {args.outfile}")
    elif args.out == "json":
        save_json(args.outfile, results)
        print(f"[+] JSON written to {args.outfile}")

    print(f"[✓] Done in {time.time() - t0:.2f}s")

if __name__ == "__main__":
    main()
