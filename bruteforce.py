#!/usr/bin/env python3
"""Simple SSH brute-force detector.

Reads an auth log, counts failed logins per IP, and flags IPs that
reach a threshold. Also warns if a flagged IP later logged in successfully.

Usage:
    python brute_force_detector.py auth.log
    python brute_force_detector.py /var/log/auth.log --threshold 10
"""

import argparse
import re
import sys
from collections import defaultdict

FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")
ACCEPTED = re.compile(r"Accepted \w+ for (\S+) from (\S+) port")


def analyze(path):
    failures = defaultdict(int)       # ip -> number of failed attempts
    usernames = defaultdict(set)      # ip -> usernames that were tried
    successes = defaultdict(list)     # ip -> users who logged in successfully

    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = FAILED.search(line)
            if m:
                user, ip = m.groups()
                failures[ip] += 1
                usernames[ip].add(user)
                continue

            m = ACCEPTED.search(line)
            if m:
                user, ip = m.groups()
                successes[ip].append(user)

    return failures, usernames, successes


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attempts in a log file.")
    parser.add_argument("logfile", help="path to the auth log")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                        help="failed attempts needed to flag an IP (default: 5)")
    args = parser.parse_args()

    try:
        failures, usernames, successes = analyze(args.logfile)
    except FileNotFoundError:
        sys.exit(f"File not found: {args.logfile}")

    if not failures:
        print("No failed login attempts found.")
        return

    print(f"{'IP address':<20}{'Failures':<10}{'Users tried':<13}Status")
    print("-" * 60)

    suspicious = 0
    for ip, count in sorted(failures.items(), key=lambda x: x[1], reverse=True):
        status = ""
        if count >= args.threshold:
            status = "SUSPICIOUS"
            suspicious += 1
            if ip in successes:
                status += " (later logged in!)"
        print(f"{ip:<20}{count:<10}{len(usernames[ip]):<13}{status}")

    print(f"\n{suspicious} suspicious IP(s) found (threshold: {args.threshold} failures).")


if __name__ == "__main__":
    main()