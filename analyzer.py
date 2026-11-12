"""Auth log analyzer: spots brute-force patterns in a Linux-style sshd auth log.

Usage:  python analyzer.py sample_auth.log -o report.csv
Standard library only.
"""
import argparse
import csv
import re
from collections import defaultdict

# ---- Settings you can tune -------------------------------------------------
FAIL_THRESHOLD = 5   # this many failures from one IP counts as suspicious
NIGHT_START = 22     # a login at or after 22:00 is "unusual"...
NIGHT_END = 6        # ...and so is one before 06:00
FIELDS = ["type", "ip", "user", "time", "details"]   # CSV column order

# Matches sshd lines such as:
# Nov  3 03:14:22 srv01 sshd[1234]: Failed password for invalid user admin from 203.0.113.50 port 52341 ssh2
# Named groups (?P<name>...) let us read the pieces by name instead of by number.
LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd\[\d+\]:\s+(?P<result>Failed|Accepted)\s+\S+\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_line(line):
    """Turn one log line into a dict, or return None if it is not a login attempt."""
    match = LINE_RE.match(line)
    if match is None:
        return None                                    # ignore CRON, sudo, other noise
    event = match.groupdict()                          # month, day, time, result, user, ip
    event["success"] = event["result"] == "Accepted"   # True / False is easier to use later
    event["hour"] = int(event["time"][:2])             # "03:14:22" -> 3
    event["when"] = f"{event['month']} {event['day']} {event['time']}"
    return event


def read_events(path):
    """Read the file and return the parsed login events, in the same order as the file."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as log:
        for line in log:
            event = parse_line(line)
            if event:                                  # skip lines that returned None
                events.append(event)
    return events


def make_alert(kind, ip, user, when, details):
    """Build one alert row. Every detector uses this, so the CSV columns always match."""
    return {"type": kind, "ip": ip, "user": user, "time": when, "details": details}


def find_brute_force(events):
    """Alert on any IP that has FAIL_THRESHOLD or more failed logins."""
    failures = defaultdict(list)                       # ip -> list of its failed events
    for e in events:
        if not e["success"]:
            failures[e["ip"]].append(e)
    alerts = []
    for ip, fails in failures.items():
        if len(fails) >= FAIL_THRESHOLD:
            names = {f["user"] for f in fails}         # a set keeps each username once
            alerts.append(make_alert(
                "BRUTE_FORCE", ip, "-", fails[0]["when"],
                f"{len(fails)} failed logins, usernames tried: {len(names)}"))
    return alerts


def find_success_after_failures(events):
    """Alert when an IP logs in successfully AFTER many failures (a possible break-in).

    Order matters here, so we walk the events top to bottom with a running count.
    """
    fail_count = defaultdict(int)                      # ip -> failures seen so far
    alerts = []
    for e in events:
        if not e["success"]:
            fail_count[e["ip"]] += 1
        elif fail_count[e["ip"]] >= FAIL_THRESHOLD:
            alerts.append(make_alert(
                "SUCCESS_AFTER_FAILURES", e["ip"], e["user"], e["when"],
                f"login succeeded after {fail_count[e['ip']]} failed attempts"))
    return alerts


def find_odd_hours(events):
    """Alert on SUCCESSFUL logins outside normal hours (failed ones are just internet noise)."""
    alerts = []
    for e in events:
        if e["success"] and (e["hour"] >= NIGHT_START or e["hour"] < NIGHT_END):
            alerts.append(make_alert(
                "ODD_HOUR_LOGIN", e["ip"], e["user"], e["when"],
                f"successful login at {e['time']}"))
    return alerts


def print_summary(events, alerts):
    """Print overall totals, then the alerts grouped by type."""
    failed = sum(1 for e in events if not e["success"])
    print("=== Auth Log Summary ===")
    print(f"Login events parsed : {len(events)}")
    print(f"  successful        : {len(events) - failed}")
    print(f"  failed            : {failed}")
    print(f"Alerts raised       : {len(alerts)}")
    for kind in sorted({a["type"] for a in alerts}):
        group = [a for a in alerts if a["type"] == kind]
        print(f"\n{kind} ({len(group)})")
        for a in group:
            print(f"  {a['ip']:<15} user={a['user']:<6} {a['time']}  {a['details']}")


def save_csv(alerts, path):
    """Write all alerts to a CSV file, with a header row."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(alerts)


def main():
    parser = argparse.ArgumentParser(description="Detect suspicious logins in an auth log.")
    parser.add_argument("logfile", help="path to the log file")
    parser.add_argument("-o", "--output", default="report.csv", help="CSV report path")
    args = parser.parse_args()

    try:
        events = read_events(args.logfile)
    except FileNotFoundError:
        raise SystemExit(f"File not found: {args.logfile}")

    alerts = (find_brute_force(events)
              + find_success_after_failures(events)
              + find_odd_hours(events))
    print_summary(events, alerts)
    save_csv(alerts, args.output)
    print(f"\nCSV report saved to {args.output}")


if __name__ == "__main__":
    main()
