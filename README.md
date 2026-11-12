# Auth Log Analyzer

A small Python tool that reads a Linux-style SSH authentication log and flags suspicious login activity. It uses only the Python standard library, and the analyzer is about 140 lines.

## What it does

The analyzer reads a log file and looks for three patterns:

| Alert | What it means |
|---|---|
| `BRUTE_FORCE` | One IP address has 5 or more failed logins (a password-guessing pattern). |
| `SUCCESS_AFTER_FAILURES` | An IP logged in **successfully after** 5 or more failures. This is the most serious alert, because the guessing may have worked. |
| `ODD_HOUR_LOGIN` | A successful login between 22:00 and 06:00. |

It prints a summary to the screen and saves every alert to a CSV file.

## Why this matters for a SOC

- Failed SSH logins are among the most common events an analyst sees. Most are internet-wide bots, so the useful skill is telling noise from a real attempt.
- Password guessing maps to MITRE ATT&CK **T1110 (Brute Force)**. A successful login with a stolen or guessed password maps to **T1078 (Valid Accounts)**.
- The key triage question is "did it work?". A pile of failures is background noise, but failures followed by a success is an incident to investigate.
- Unusual-hour logins are a classic anomaly. They are not proof of anything, but they tell an analyst where to look first.
- The CSV output shows how detections can be passed on to a ticketing system, a SIEM, or a spreadsheet for review.

## Project files

| File | Purpose |
|---|---|
| `analyzer.py` | The analyzer (the main program). |
| `generate_logs.py` | Creates a **fake** log with made-up users and IPs. |
| `test_analyzer.py` | Automated tests. |
| `sample_auth.log` | A sample log created by the generator. |
| `report.csv` | The report created from the sample log. |

All sample IPs come from the ranges reserved for documentation (RFC 5737: `192.0.2.x`, `198.51.100.x`, `203.0.113.x`). They never belong to real machines, and no real data is used.

## How to run

You need Python 3.8 or newer. Nothing needs to be installed.

```bash
python generate_logs.py                          # creates sample_auth.log (fake data)
python analyzer.py sample_auth.log -o report.csv # analyzes it, prints a summary, saves the CSV
python -m unittest -v                            # runs the tests
```

On a real Linux server you can point it at `/var/log/auth.log` (Debian/Ubuntu). On RHEL-based systems the file is `/var/log/secure`.

## Example output

```
=== Auth Log Summary ===
Login events parsed : 44
  successful        : 14
  failed            : 30
Alerts raised       : 4

BRUTE_FORCE (2)
  203.0.113.50    user=-      Nov 4 03:00:02  14 failed logins, usernames tried: 5
  203.0.113.77    user=-      Nov 5 14:05:03  7 failed logins, usernames tried: 1

ODD_HOUR_LOGIN (1)
  198.51.100.11   user=bob    Nov 5 02:47:00  successful login at 02:47:00

SUCCESS_AFTER_FAILURES (1)
  203.0.113.77    user=carol  Nov 5 14:05:25  login succeeded after 7 failed attempts

CSV report saved to report.csv
```

The sample log also contains one IP with only 4 failures. It is correctly **not** flagged, which shows the threshold working.

## How the code works (plain-language explanations)

**Settings at the top.** `FAIL_THRESHOLD` (5), `NIGHT_START` (22) and `NIGHT_END` (6) are constants. Changing a number there changes the behavior of the whole tool.

**`LINE_RE` (the regular expression).** This is a pattern that describes what a login line looks like. It pulls out the date, time, result (`Failed` or `Accepted`), username and IP address. Lines that do not match, such as cron or sudo messages, are ignored.

**`parse_line(line)`.** Takes one text line and returns a dictionary such as `{"ip": ..., "user": ..., "success": True/False, "hour": 3, ...}`. If the line is not a login attempt, it returns `None`.

**`read_events(path)`.** Opens the file, runs `parse_line` on every line, and keeps only the lines that were real login events. The events stay in file order, which matters later.

**`make_alert(...)`.** A tiny helper that builds one alert as a dictionary. All three detectors use it, so every alert has the same fields and the CSV columns always line up.

**`find_brute_force(events)`.** Groups the failed logins by IP address. Any IP with 5 or more failures becomes an alert. It also counts how many different usernames that IP tried, because many usernames suggests guessing.

**`find_success_after_failures(events)`.** Walks through the events from top to bottom, keeping a running count of failures per IP. If a successful login arrives from an IP whose count is already 5 or more, it raises an alert. Because it goes in order, a success *before* the failures is not flagged.

**`find_odd_hours(events)`.** Flags successful logins where the hour is 22 or later, or before 6. Failed attempts are skipped on purpose, because bots try at all hours.

**`print_summary(events, alerts)`.** Prints the totals (events, successes, failures, alerts) and then the alerts grouped by type.

**`save_csv(alerts, path)`.** Writes the alerts to a CSV file with a header row, using Python's built-in `csv` module.

**`main()`.** Reads the command-line arguments (the log path and an optional `-o` output path), runs the three detectors, prints the summary and saves the CSV. It prints a clean error if the file does not exist.

## Limitations and ideas for improvement

- Failures are counted over the whole file. A real tool would count them inside a **time window**, for example 5 failures in 2 minutes.
- Syslog timestamps have no year or time zone, so the tool treats the times as the server's local time.
- It only understands IPv4 addresses and the standard `sshd` password-style messages.
- "Unusual hour" is the same for every user. A better version would learn each user's normal hours.
- It cannot tell whether an IP is shared (for example, many people behind one office NAT address), which can cause false positives.
- Possible next steps: IP allow-lists, GeoIP lookup, support for other log sources, and sending alerts to a SIEM.

## What I learned

- How an SSH authentication log is structured, and which fields matter for detection.
- How to use regular expressions with named groups to turn messy text into structured data.
- How `defaultdict` makes counting and grouping short and readable.
- Why detection order matters: "success after failures" is a different question from "many failures".
- How thresholds trade off false positives against missed attacks.
- How to write tests that check boundaries (4 failures vs. 5, 21:00 vs. 22:00), not only the obvious cases.
- How to generate safe fake test data using reserved documentation IP ranges.

## Built with AI

This project was built with AI coding tools, then reviewed and tested by me.
