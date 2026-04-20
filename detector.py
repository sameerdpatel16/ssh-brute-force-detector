#!/usr/bin/env python3
"""
SSH brute force detector. Reads /var/log/auth.log (or any auth log),
finds IPs with excessive failed logins, and flags anything that eventually
got in after hammering the server.

Usage:
  python detector.py --generate-sample     # make a test log
  python detector.py sample_auth.log       # run against it
  python detector.py /var/log/auth.log     # real server

Author: sameerdpatel16
"""

import re
import sys
import argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path


# auth.log lines we care about:
#   Nov 13 04:12:01 host sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2
#   Nov 13 04:12:05 host sshd[1234]: Accepted password for sameer from 1.2.3.4 port 22345 ssh2
FAILED_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)
SUCCESS_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)
DISCONNECT_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*Disconnected from authenticating user (\S+) (\d+\.\d+\.\d+\.\d+)"
)


def parse_log(filepath: str) -> tuple:
    failed_attempts   = defaultdict(list)
    successful_logins = defaultdict(list)
    total_lines       = 0
    matched_lines     = 0

    path = Path(filepath)
    if not path.exists():
        print(f"[!] Log file not found: {filepath}")
        sys.exit(1)

    print(f"[*] Parsing: {filepath}")

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            total_lines += 1

            match = FAILED_PATTERN.search(line)
            if match:
                timestamp, username, ip = match.groups()
                failed_attempts[ip].append((timestamp, username))
                matched_lines += 1
                continue

            match = SUCCESS_PATTERN.search(line)
            if match:
                timestamp, username, ip = match.groups()
                successful_logins[ip].append((timestamp, username))
                matched_lines += 1

    print(f"[*] {total_lines:,} lines processed, {matched_lines:,} SSH events found")
    return failed_attempts, successful_logins


# thresholds are somewhat arbitrary but 100+ failed attempts is never a typo
THRESHOLDS = {"CRITICAL": 100, "HIGH": 20, "MEDIUM": 5, "LOW": 1}

def classify_severity(count: int) -> str:
    if count >= THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    elif count >= THRESHOLDS["HIGH"]:
        return "HIGH"
    elif count >= THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def analyse(failed_attempts: dict, successful_logins: dict, min_attempts: int) -> list:
    results = []

    for ip, attempts in failed_attempts.items():
        count = len(attempts)
        if count < min_attempts:
            continue

        targeted_users = list(set(u for _, u in attempts))
        timestamps     = [t for t, _ in attempts]
        successful     = successful_logins.get(ip, [])

        results.append({
            "ip":             ip,
            "count":          count,
            "severity":       classify_severity(count),
            "targeted_users": targeted_users,
            "unique_users":   len(targeted_users),
            "first_seen":     timestamps[0],
            "last_seen":      timestamps[-1],
            "breached":       len(successful) > 0,
            "breached_users": list(set(u for _, u in successful)) if successful else [],
        })

    results.sort(key=lambda x: x["count"], reverse=True)
    return results


SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
}
RESET = "\033[0m"

def severity_label(severity: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}[{severity}]{RESET}"


def print_report(results: list, successful_logins: dict, failed_attempts: dict):
    total_failed  = sum(len(v) for v in failed_attempts.values())
    total_success = sum(len(v) for v in successful_logins.values())

    print(f"\n{'='*60}")
    print(f"  SSH BRUTE FORCE DETECTION REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"\n  Failed login attempts : {total_failed:,}")
    print(f"  Successful logins     : {total_success:,}")
    print(f"  Suspicious IPs        : {len(results)}")

    if not results:
        print("\n  [+] Nothing suspicious above threshold.")
        print(f"{'='*60}\n")
        return

    # breaches are the most important thing — surface them first
    breached = [r for r in results if r["breached"]]
    if breached:
        print(f"\n  {'!'*50}")
        print(f"  ALERT: {len(breached)} IP(s) broke in after brute forcing")
        print(f"  {'!'*50}")
        for r in breached:
            print(f"  {r['ip']} logged in as: {', '.join(r['breached_users'])}")

    print(f"\n  {'─'*58}")
    print(f"  {'IP ADDRESS':<18} {'SEVERITY':<12} {'ATTEMPTS':<10} {'USERS TRIED':<12} {'BREACHED'}")
    print(f"  {'─'*58}")

    for r in results:
        print(
            f"  {r['ip']:<18} "
            f"{severity_label(r['severity']):<20} "
            f"{r['count']:<10} "
            f"{r['unique_users']:<12} "
            f"{'YES ⚠' if r['breached'] else 'no'}"
        )

    # detailed view for the bad ones
    print(f"\n  {'─'*58}")
    print(f"  CRITICAL & HIGH — details")
    print(f"  {'─'*58}")

    detailed = [r for r in results if r["severity"] in ("CRITICAL", "HIGH")]
    if not detailed:
        print("  None.")
    else:
        for r in detailed:
            print(f"\n  IP: {r['ip']}  {severity_label(r['severity'])}")
            print(f"    Attempts   : {r['count']:,}")
            print(f"    First seen : {r['first_seen']}")
            print(f"    Last seen  : {r['last_seen']}")
            users = r['targeted_users'][:10]
            if len(r['targeted_users']) > 10:
                users.append(f"... +{len(r['targeted_users']) - 10} more")
            print(f"    Targeted   : {', '.join(users)}")
            if r["breached"]:
                print(f"    ⚠ BREACHED : logged in as {', '.join(r['breached_users'])}")

    # which usernames are attackers most commonly guessing?
    # useful for knowing what your exposed services look like from the outside
    all_targeted = defaultdict(int)
    for ip, attempts in failed_attempts.items():
        for _, username in attempts:
            all_targeted[username] += 1

    top_users = sorted(all_targeted.items(), key=lambda x: x[1], reverse=True)[:10]
    print(f"\n  {'─'*58}")
    print(f"  TOP TARGETED USERNAMES")
    print(f"  {'─'*58}")
    for username, count in top_users:
        bar = "█" * min(count // 5, 30)
        print(f"  {username:<20} {count:>6}x  {bar}")

    print(f"\n{'='*60}\n")


def save_report(results: list, output_path: str):
    with open(output_path, "w") as f:
        f.write(f"SSH Brute Force Detection Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"{'IP':<18} {'Severity':<10} {'Attempts':<10} {'Users Tried':<12} {'Breached'}\n")
        f.write("-" * 60 + "\n")
        for r in results:
            f.write(
                f"{r['ip']:<18} {r['severity']:<10} {r['count']:<10} "
                f"{r['unique_users']:<12} {'YES' if r['breached'] else 'no'}\n"
            )
    print(f"[*] Report saved to: {output_path}")


def generate_sample_log(output_path: str):
    """Generates a realistic fake auth.log so you can test without a real server."""
    import random

    attackers = {
        "185.220.101.45": {"attempts": 450, "users": ["root","admin","ubuntu","pi","test","oracle","postgres"]},
        "45.142.212.100": {"attempts": 87,  "users": ["root","admin","user"]},
        "103.99.115.22":  {"attempts": 23,  "users": ["root","deploy"]},
        "10.0.0.99":      {"attempts": 3,   "users": ["root"]},
        "192.168.1.200":  {"attempts": 520, "users": ["root","admin","sameer"], "breach": ("sameer", True)},
    }

    lines = []
    month, day = "Nov", 13

    for ip, data in attackers.items():
        for i in range(data["attempts"]):
            ts   = f"{month} {day:2d} {random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
            user = random.choice(data["users"])
            port = random.randint(30000, 65000)
            lines.append(
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {'invalid user ' if user not in ['root','sameer'] else ''}"
                f"{user} from {ip} port {port} ssh2\n"
            )

        if data.get("breach"):
            lines.append(
                f"{month} {day:2d} 23:59:01 server sshd[9999]: "
                f"Accepted password for {data['breach'][0]} from {ip} port 55555 ssh2\n"
            )

    for i in range(5):
        lines.append(
            f"Nov {day:2d} 09:{i:02d}:00 server sshd[1111]: "
            f"Accepted password for sameer from 192.168.1.5 port 22222 ssh2\n"
        )

    random.shuffle(lines)

    with open(output_path, "w") as f:
        f.writelines(lines)

    print(f"[*] Sample log written to {output_path} ({len(lines):,} lines)")


def main():
    parser = argparse.ArgumentParser(
        description="SSH brute force detector — parses auth.log and reports attack patterns",
        epilog=(
            "Examples:\n"
            "  python detector.py --generate-sample\n"
            "  python detector.py sample_auth.log\n"
            "  python detector.py /var/log/auth.log -m 10 -o report.txt"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("logfile",            nargs="?",           help="Path to auth.log")
    parser.add_argument("-m", "--min",        default=5, type=int, help="Min failed attempts to report (default: 5)")
    parser.add_argument("-o", "--output",     default=None,        help="Save report to file")
    parser.add_argument("--generate-sample",  action="store_true", help="Generate a sample auth.log for testing")

    args = parser.parse_args()

    if args.generate_sample:
        generate_sample_log("sample_auth.log")
        print("[*] Run: python detector.py sample_auth.log")
        return

    if not args.logfile:
        parser.print_help()
        sys.exit(1)

    failed_attempts, successful_logins = parse_log(args.logfile)
    results = analyse(failed_attempts, successful_logins, args.min)
    print_report(results, successful_logins, failed_attempts)

    if args.output:
        save_report(results, args.output)


if __name__ == "__main__":
    main()
