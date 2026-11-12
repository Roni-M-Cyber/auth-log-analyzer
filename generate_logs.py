"""Generate a FAKE auth log for testing the analyzer. No real data is used.

All IPs come from the RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x,
203.0.113.x). Those ranges are reserved for examples and never belong to a real host.

Usage:  python generate_logs.py [output_file]     (default: sample_auth.log)
"""
import random
import sys
from datetime import datetime, timedelta

random.seed(42)                    # same seed = same log every run (repeatable)
START = datetime(2026, 11, 3)      # made-up first day of the log
USER_IPS = {"alice": "198.51.100.10", "bob": "198.51.100.11",
            "carol": "198.51.100.12", "dave": "198.51.100.13"}
KNOWN_USERS = set(USER_IPS) | {"root"}    # any other name gets "invalid user" in the log


def stamp(when):
    """Format a time like real syslog does; the day is padded with a space ('Nov  3')."""
    return f"{when:%b} {when.day:>2} {when:%H:%M:%S}"


def make_line(when, ok, user, ip):
    """Build one sshd-style line. Returns (time, text) so rows can be sorted by time."""
    pid, port = random.randint(1000, 30000), random.randint(1024, 65535)
    outcome = "Accepted" if ok else "Failed"
    who = user if (ok or user in KNOWN_USERS) else f"invalid user {user}"
    return when, f"{stamp(when)} srv01 sshd[{pid}]: {outcome} password for {who} from {ip} port {port} ssh2"


def build_rows():
    """Create every fake scenario and return the rows (not yet sorted)."""
    rows = []

    # 1) Normal behaviour: each user logs in once a day in office hours,
    #    sometimes after one mistyped password.
    for day in range(3):
        for user, ip in USER_IPS.items():
            when = START + timedelta(days=day, hours=random.randint(8, 17),
                                     minutes=random.randint(0, 59), seconds=random.randint(0, 59))
            if random.random() < 0.3:
                rows.append(make_line(when - timedelta(seconds=20), False, user, ip))
            rows.append(make_line(when, True, user, ip))

    # 2) Brute force: one attacker IP tries common usernames and never gets in.
    when = START + timedelta(days=1, hours=3)
    for _ in range(14):
        when += timedelta(seconds=random.randint(2, 6))
        guess = random.choice(["admin", "root", "test", "oracle", "ubuntu"])
        rows.append(make_line(when, False, guess, "203.0.113.50"))

    # 3) Break-in: 7 failures against carol's account, then the correct password.
    when = START + timedelta(days=2, hours=14, minutes=5)
    for _ in range(7):
        when += timedelta(seconds=3)
        rows.append(make_line(when, False, "carol", "203.0.113.77"))
    rows.append(make_line(when + timedelta(seconds=4), True, "carol", "203.0.113.77"))

    # 4) Unusual hour: bob logs in from his usual IP at 02:47.
    rows.append(make_line(START + timedelta(days=2, hours=2, minutes=47), True, "bob", USER_IPS["bob"]))

    # 5) Below the threshold: only 4 failures, so this should NOT be flagged.
    when = START + timedelta(hours=11)
    for _ in range(4):
        when += timedelta(seconds=5)
        rows.append(make_line(when, False, "dave", "192.0.2.99"))

    # 6) Unrelated noise the analyzer must ignore.
    noise_time = START + timedelta(hours=9)
    rows.append((noise_time, f"{stamp(noise_time)} srv01 CRON[2211]: pam_unix(cron:session): session opened for user root"))
    return rows


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_auth.log"
    rows = sorted(build_rows(), key=lambda row: row[0])    # oldest first, like a real log
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(text for _, text in rows) + "\n")
    print(f"Wrote {len(rows)} fake log lines to {path}")


if __name__ == "__main__":
    main()
