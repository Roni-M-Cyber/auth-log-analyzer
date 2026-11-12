"""Simple tests for analyzer.py. Run with:  python -m unittest -v"""
import csv
import os
import tempfile
import unittest

import analyzer

N = analyzer.FAIL_THRESHOLD   # so the tests keep working if you change the threshold


def line(ok=False, ip="203.0.113.5", hour=10, user="alice"):
    """Build one fake log line, so each test can say exactly what it needs."""
    word = "Accepted" if ok else "Failed"
    return f"Nov  3 {hour:02d}:15:00 srv01 sshd[100]: {word} password for {user} from {ip} port 5000 ssh2"


def parse_all(*lines):
    """Parse several lines the same way read_events does."""
    return [analyzer.parse_line(text) for text in lines]


class ParseTests(unittest.TestCase):
    def test_failed_line_fields(self):
        e = analyzer.parse_line(line(ok=False, hour=3, user="bob", ip="192.0.2.7"))
        self.assertFalse(e["success"])
        self.assertEqual((e["user"], e["ip"], e["hour"]), ("bob", "192.0.2.7", 3))

    def test_invalid_user_prefix_is_removed(self):
        text = "Nov  3 03:00:00 srv01 sshd[1]: Failed password for invalid user admin from 192.0.2.7 port 22 ssh2"
        self.assertEqual(analyzer.parse_line(text)["user"], "admin")

    def test_unrelated_line_is_ignored(self):
        self.assertIsNone(analyzer.parse_line("Nov  3 09:00:01 srv01 CRON[2211]: session opened"))


class DetectorTests(unittest.TestCase):
    def test_brute_force_flagged_at_threshold_only(self):
        self.assertEqual(len(analyzer.find_brute_force(parse_all(*[line()] * N))), 1)
        self.assertEqual(len(analyzer.find_brute_force(parse_all(*[line()] * (N - 1)))), 0)

    def test_failures_are_counted_per_ip(self):
        lines = [line(ip="192.0.2.1")] * (N - 1) + [line(ip="192.0.2.2")] * (N - 1)
        self.assertEqual(analyzer.find_brute_force(parse_all(*lines)), [])

    def test_success_after_failures_flagged(self):
        events = parse_all(*[line()] * N, line(ok=True))
        alerts = analyzer.find_success_after_failures(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "SUCCESS_AFTER_FAILURES")

    def test_success_before_failures_not_flagged(self):
        events = parse_all(line(ok=True), *[line()] * N)    # order matters
        self.assertEqual(analyzer.find_success_after_failures(events), [])

    def test_odd_hour_boundaries(self):
        flagged = lambda hour, ok=True: len(analyzer.find_odd_hours(parse_all(line(ok=ok, hour=hour))))
        self.assertEqual(flagged(2), 1)                     # night: flagged
        self.assertEqual(flagged(22), 1)                    # first "night" hour
        self.assertEqual(flagged(21), 0)                    # just before night
        self.assertEqual(flagged(6), 0)                     # first "day" hour
        self.assertEqual(flagged(10), 0)                    # normal hours
        self.assertEqual(flagged(3, ok=False), 0)           # failed logins are not flagged


class CsvTests(unittest.TestCase):
    def test_csv_has_header_and_rows(self):
        alerts = [analyzer.make_alert("BRUTE_FORCE", "192.0.2.1", "-", "Nov 3 03:00:00", "test")]
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "report.csv")
            analyzer.save_csv(alerts, path)
            with open(path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["type"], "BRUTE_FORCE")
        self.assertEqual(list(rows[0]), analyzer.FIELDS)


if __name__ == "__main__":
    unittest.main()
