# SSH Brute Force Detector

A Python tool that parses Linux auth logs to detect SSH brute force attacks, classify attacker severity, and identify breached accounts.

## How SSH Brute Force Attacks Work

SSH (port 22) is one of the most attacked services on the internet. Attackers run automated tools that try thousands of username/password combinations per minute. Every failed attempt leaves a trace in `/var/log/auth.log`:

```
Nov 13 04:12:01 server sshd[1234]: Failed password for root from 185.220.101.45 port 54321 ssh2
Nov 13 04:12:01 server sshd[1234]: Failed password for invalid user admin from 185.220.101.45 port 54322 ssh2
```

This tool reads those logs, groups failures by attacker IP, classifies severity, and flags any IPs that eventually succeeded — meaning a breach occurred.

## Quick Start

```bash
# 1. Generate a realistic sample log to test with
python detector.py --generate-sample

# 2. Run the detector against it
python detector.py sample_auth.log

# 3. Save the report to a file
python detector.py sample_auth.log -o report.txt
```

## Real Usage (on a Linux server)

```bash
# Analyse your actual SSH logs
python detector.py /var/log/auth.log

# Only report IPs with 20+ attempts (filter out noise)
python detector.py /var/log/auth.log -m 20

# Save full report
python detector.py /var/log/auth.log -m 10 -o ssh_report.txt
```

## Example Output

```
[*] Parsing log file: sample_auth.log
[*] Processed 1,088 lines — 1,083 SSH auth events found

============================================================
  SSH BRUTE FORCE DETECTION REPORT
  Generated: 2025-11-13 14:22:01
============================================================

  Total failed login attempts : 1,083
  Total successful logins     : 6
  Suspicious IPs detected     : 4

  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ALERT: 1 IP(s) successfully broke in after brute forcing!
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  IP: 192.168.1.200 | Logged in as: sameer

  ──────────────────────────────────────────────────────────
  IP ADDRESS         SEVERITY     ATTEMPTS   USERS TRIED  BREACHED
  ──────────────────────────────────────────────────────────
  185.220.101.45     [CRITICAL]   450        7            no
  192.168.1.200      [CRITICAL]   520        3            YES ⚠
  45.142.212.100     [HIGH]       87         3            no
  103.99.115.22      [MEDIUM]     23         2            no

  TOP TARGETED USERNAMES (attacker wordlists)
  ──────────────────────────────────────────────────────────
  root                  892x  ██████████████████████████████
  admin                 201x  ████████
  ubuntu                 88x  ███
```

## Severity Classification

| Level    | Failed Attempts | Meaning |
|----------|----------------|---------|
| CRITICAL | 100+           | Definite automated brute force |
| HIGH     | 20–99          | Very suspicious, likely automated |
| MEDIUM   | 5–19           | Suspicious, possible manual probing |
| LOW      | 1–4            | Possible typo, low risk |

## Detection Logic

The tool detects these attack patterns:

- **Volume-based**: IPs with unusually high failed login counts
- **Username spraying**: Attackers trying many different usernames (credential stuffing)
- **Successful breach**: An IP that failed many times then succeeded — the most dangerous finding
- **Common wordlist patterns**: Top targeted usernames reveal attacker wordlists (root, admin, ubuntu, pi)

## Use in a Real SOC

In a real Security Operations Center (SOC), this type of log analysis feeds into a **SIEM** (Security Information and Event Management) system like Splunk or Security Onion. The output of this tool could be used to:

- Automatically block attacker IPs via `iptables` or `fail2ban`
- Trigger alerts to security analysts
- Feed threat intelligence databases

## Lab Demo

If you have a Kali + vulnerable VM lab, you can generate real attack data:

```bash
# From Kali — run a brute force with Hydra
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>

# Then analyse the auth.log on the target VM
python detector.py /var/log/auth.log
```

This lets you see your own attack reflected in the logs — a great way to understand both offensive and defensive perspectives.

## Legal Notice

Only use against systems you own or have explicit written permission to test.
