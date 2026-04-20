#!/usr/bin/env python3
"""
SSH Brute Force Detector
========================
Parses Linux auth logs to detect SSH brute force attacks.

How SSH brute force attacks work:
  An attacker repeatedly tries username/password combinations against SSH
  (port 22). Each failed attempt leaves a line in /var/log/auth.log like:
    "Failed password for root from 192.168.1.5 port 54321 ssh2"

  A single failed login could be a typo. But 500 failures in 60 seconds
  from the same IP is clearly an automated attack.

  This tool:
    1. Parses auth.log and extracts failed login attempts
    2. Groups them by attacker IP
    3. Applies threshold rules to classify IPs as suspicious/attacking
    4. Reports targeted usernames (tells you what attackers are guessing)
    5. Generates a summary report

Author: sameerdpatel16
"""

import re
import sys
import argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# STEP 1: Define what we're looking for in the log
# ---------------------------------------------------------------------------
# auth.log lines look like this:
#   Nov 13 04:12:01 hostname sshd[1234]: Failed password for root from 192.168.1.5 port 54321 ssh2
#   Nov 13 04:12:02 hostname sshd[1234]: Failed password for invalid user admin from 10.0.0.2 port 44321 ssh2
#   Nov 13 04:12:05 hostname sshd[1234]: Accepted password for sameer from 192.168.1.10 port 22345 ssh2
#
# We use regex to extract: timestamp, username, IP address, and whether it
# was a success or failure.

# Matches failed login attempts — captures the username and IP
FAILED_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# Matches successful logins — useful to flag IPs that eventually got in
SUCCESS_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# Matches connection closed / disconnect lines — for context
DISCONNECT_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*Disconnected from authenticating user (\S+) (\d+\.\d+\.\d+\.\d+)"
)


# ---------------------------------------------------------------------------
# STEP 2: Parse the log file
# ---------------------------------------------------------------------------
# We read every line and try to match our patterns.
# We track:
#   - failed_attempts: { ip -> list of (timestamp, username) }
#   - successful_logins: { ip -> list of (timestamp, username) }

def parse_log(filepath: str) -> tuple:
    failed_attempts  = defaultdict(list)   # ip -> [(timestamp, username), ...]
    successful_logins = defaultdict(list)  # ip -> [(timestamp, username), ...]
    total_lines      = 0
    matched_lines    = 0

    path = Path(filepath)
    if not path.exists():
        print(f"[!] Log file not found: {filepath}")
        sys.exit(1)

    print(f"[*] Parsing log file: {filepath}")

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            total_lines += 1

            # Check for failed attempts
            match = FAILED_PATTERN.search(line)
            if match:
                timestamp, username, ip = match.groups()
                failed_attempts[ip].append((timestamp, username))
                matched_lines += 1
                continue

            # Check for successful logins
            match = SUCCESS_PATTERN.search(line)
            if match:
                timestamp, username, ip = match.groups()
                successful_logins[ip].append((timestamp, username))
                matched_lines += 1

    print(f"[*] Processed {total_lines:,} lines — {matched_lines:,} SSH auth events found")
    return failed_attempts, successful_logins


# ---------------------------------------------------------------------------
# STEP 3: Analyse the data
# ---------------------------------------------------------------------------
# Raw counts aren't enough — we need to classify each IP.
#
# Classification:
#   CRITICAL  — 100+ failed attempts  (definitely a brute force attack)
#   HIGH      — 20–99 failed attempts (very suspicious, likely automated)
#   MEDIUM    — 5–19 failed attempts  (suspicious, could be manual probing)
#   LOW       — 1–4 failed attempts   (could be a legitimate typo)
#
# We also flag IPs that:
#   - Tried many different usernames (typical of credential stuffing)
#   - Eventually succeeded after many failures (successful brute force!)

THRESHOLDS = {
    "CRITICAL": 100,
    "HIGH":     20,
    "MEDIUM":   5,
    "LOW":      1,
}

def classify_severity(count: int) -> str:
    if count >= THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    elif count >= THRESHOLDS["HIGH"]:
        return "HIGH"
    elif count >= THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    else:
        return "LOW"

def analyse(failed_attempts: dict, successful_logins: dict, min_attempts: int) -> list:
    results = []

    for ip, attempts in failed_attempts.items():
        count = len(attempts)

        # Skip IPs below the minimum threshold (ignore one-off typos if desired)
        if count < min_attempts:
            continue

        # Which usernames did this IP target?
        targeted_users = list(set(u for _, u in attempts))

        # First and last seen timestamps
        timestamps = [t for t, _ in attempts]
        first_seen = timestamps[0]
        last_seen  = timestamps[-1]

        # Did this IP ever successfully log in?
        successful = successful_logins.get(ip, [])
        breached = len(successful) > 0
        breached_users = list(set(u for _, u in successful)) if breached else []

        results.append({
            "ip":              ip,
            "count":           count,
            "severity":        classify_severity(count),
            "targeted_users":  targeted_users,
            "unique_users":    len(targeted_users),
            "first_seen":      first_seen,
            "last_seen":       last_seen,
            "breached":        breached,
            "breached_users":  breached_users,
        })

    # Sort by count descending (worst offenders first)
    results.sort(key=lambda x: x["count"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# STEP 4: Print the report
# ---------------------------------------------------------------------------
# A clear, readable report that shows what happened and who did it.
# In a real SOC (Security Operations Center), this would feed into a SIEM.

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH":     "\033[93m",  # Yellow
    "MEDIUM":   "\033[94m",  # Blue
    "LOW":      "\033[92m",  # Green
}
RESET = "\033[0m"

def severity_label(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}[{severity}]{RESET}"

def print_report(results: list, successful_logins: dict, failed_attempts: dict):
    total_failed  = sum(len(v) for v in failed_attempts.values())
    total_success = sum(len(v) for v in successful_logins.values())
    attacking_ips = len(results)

    # Header
    print(f"\n{'='*60}")
    print(f"  SSH BRUTE FORCE DETECTION REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"\n  Total failed login attempts : {total_failed:,}")
    print(f"  Total successful logins     : {total_success:,}")
    print(f"  Suspicious IPs detected     : {attacking_ips}")

    if not results:
        print("\n  [+] No suspicious activity detected above threshold.")
        print(f"{'='*60}\n")
        return

    # Breached IPs — most critical, show first
    breached = [r for r in results if r["breached"]]
    if breached:
        print(f"\n  {'!'*50}")
        print(f"  ALERT: {len(breached)} IP(s) successfully broke in after brute forcing!")
        print(f"  {'!'*50}")
        for r in breached:
            print(f"  IP: {r['ip']} | Logged in as: {', '.join(r['breached_users'])}")

    # Full breakdown per IP
    print(f"\n  {'─'*58}")
    print(f"  {'IP ADDRESS':<18} {'SEVERITY':<12} {'ATTEMPTS':<10} {'USERS TRIED':<12} {'BREACHED'}")
    print(f"  {'─'*58}")

    for r in results:
        breached_str = "YES ⚠" if r["breached"] else "no"
        print(
            f"  {r['ip']:<18} "
            f"{severity_label(r['severity']):<20} "
            f"{r['count']:<10} "
            f"{r['unique_users']:<12} "
            f"{breached_str}"
        )

    # Detailed breakdown for CRITICAL and HIGH
    print(f"\n  {'─'*58}")
    print(f"  DETAILED BREAKDOWN (CRITICAL & HIGH only)")
    print(f"  {'─'*58}")

    detailed = [r for r in results if r["severity"] in ("CRITICAL", "HIGH")]
    if not detailed:
        print("  None.")
    else:
        for r in detailed:
            print(f"\n  IP: {r['ip']}  {severity_label(r['severity'])}")
            print(f"    Attempts    : {r['count']:,}")
            print(f"    First seen  : {r['first_seen']}")
            print(f"    Last seen   : {r['last_seen']}")
            users_display = r['targeted_users'][:10]
            if len(r['targeted_users']) > 10:
                users_display.append(f"... +{len(r['targeted_users']) - 10} more")
            print(f"    Targeted    : {', '.join(users_display)}")
            if r["breached"]:
                print(f"    ⚠ BREACHED  : Logged in as {', '.join(r['breached_users'])}")

    # Most targeted usernames across all attacks
    all_targeted = defaultdict(int)
    for ip, attempts in failed_attempts.items():
        for _, username in attempts:
            all_targeted[username] += 1

    top_users = sorted(all_targeted.items(), key=lambda x: x[1], reverse=True)[:10]
    print(f"\n  {'─'*58}")
    print(f"  TOP TARGETED USERNAMES (attacker wordlists)")
    print(f"  {'─'*58}")
    for username, count in top_users:
        bar = "█" * min(count // 5, 30)
        print(f"  {username:<20} {count:>6}x  {bar}")

    print(f"\n{'='*60}\n")


# ---------------------------------------------------------------------------
# STEP 5: Optional — save report to file
# ---------------------------------------------------------------------------

def save_report(results: list, output_path: str):
    with open(output_path, "w") as f:
        f.write(f"SSH Brute Force Detection Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"{'IP':<18} {'Severity':<10} {'Attempts':<10} {'Users Tried':<12} {'Breached'}\n")
        f.write("-" * 60 + "\n")
        for r in results:
            breached_str = "YES" if r["breached"] else "no"
            f.write(
                f"{r['ip']:<18} {r['severity']:<10} {r['count']:<10} "
                f"{r['unique_users']:<12} {breached_str}\n"
            )
    print(f"[*] Report saved to: {output_path}")


# ---------------------------------------------------------------------------
# STEP 6: Generate a sample log for testing
# ---------------------------------------------------------------------------
# Since most people don't have a real auth.log handy, we generate a
# realistic fake one so the tool can be demoed immediately.

def generate_sample_log(output_path: str):
    import random

    attackers = {
        "185.220.101.45": {"attempts": 450, "users": ["root","admin","ubuntu","pi","test","oracle","postgres"]},
        "45.142.212.100": {"attempts": 87,  "users": ["root","admin","user"]},
        "103.99.115.22":  {"attempts": 23,  "users": ["root","deploy"]},
        "10.0.0.99":      {"attempts": 3,   "users": ["root"]},
        "192.168.1.200":  {"attempts": 520, "users": ["root","admin","sameer"], "breach": ("sameer", True)},
    }

    lines = []
    months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    month = "Nov"
    day = 13

    for ip, data in attackers.items():
        users = data["users"]
        for i in range(data["attempts"]):
            hour   = random.randint(0, 23)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            user   = random.choice(users)
            port   = random.randint(30000, 65000)
            ts     = f"{month} {day:2d} {hour:02d}:{minute:02d}:{second:02d}"
            lines.append(
                f"{ts} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {'invalid user ' if user not in ['root','sameer'] else ''}"
                f"{user} from {ip} port {port} ssh2\n"
            )

        # If this IP breached — add a success line at the end
        if data.get("breach"):
            breach_user = data["breach"][0]
            lines.append(
                f"{month} {day:2d} 23:59:01 server sshd[9999]: "
                f"Accepted password for {breach_user} from {ip} port 55555 ssh2\n"
            )

    # Add some legitimate logins from a trusted IP
    for i in range(5):
        lines.append(
            f"Nov {day:2d} 09:{i:02d}:00 server sshd[1111]: "
            f"Accepted password for sameer from 192.168.1.5 port 22222 ssh2\n"
        )

    # Shuffle so timestamps aren't grouped by IP
    random.shuffle(lines)

    with open(output_path, "w") as f:
        f.writelines(lines)

    print(f"[*] Sample log generated: {output_path} ({len(lines):,} lines)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SSH Brute Force Detector — parses auth.log and reports attack patterns",
        epilog="Examples:\n"
               "  python detector.py --generate-sample          # create a test log\n"
               "  python detector.py sample_auth.log            # analyse it\n"
               "  python detector.py /var/log/auth.log -m 10    # real log, 10+ attempts\n"
               "  python detector.py sample_auth.log -o report.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("logfile",         nargs="?",            help="Path to auth.log file")
    parser.add_argument("-m", "--min",     default=5, type=int,  help="Minimum failed attempts to report (default: 5)")
    parser.add_argument("-o", "--output",  default=None,         help="Save report to a text file")
    parser.add_argument("--generate-sample", action="store_true", help="Generate a sample auth.log for testing")

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
