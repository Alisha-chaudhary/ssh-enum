"""
log_parser.py — /var/log/auth.log Parser for SSH Events

Parses the four main SSH-related log patterns relevant to enumeration detection:

  1. Failed password (known or unknown user)
  2. Invalid user (explicit rejection before auth)
  3. Connection closed (before auth — banner-only probes)
  4. Accepted password (successful login — useful for baseline)
  5. Disconnected (disconnect before auth — likely banner fingerprint)

The distinction between "Failed password for invalid user X" and
"Failed password for X" (without "invalid user") is itself a historical
information leak in older OpenSSH versions. Modern versions suppress this
distinction — but we still parse both patterns for completeness.
"""

import re
from datetime import datetime
from typing import List, Dict, Optional


class LogParser:
    """
    Parse SSH authentication events from /var/log/auth.log.

    Supports both traditional syslog format and systemd journal export format.
    """

    # -----------------------------------------------------------------------
    # Regex patterns — ordered by specificity (most specific first)
    # -----------------------------------------------------------------------

    # Failed password for invalid user <name> from <ip> port <port> <method>
    _INVALID_USER_FAILED = re.compile(
        r"(?P<ts>\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: "
        r"Failed password for invalid user (?P<user>\S+) "
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    )

    # Failed password for <name> from <ip> port <port> <method>
    _VALID_USER_FAILED = re.compile(
        r"(?P<ts>\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: "
        r"Failed password for (?P<user>\S+) "
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    )

    # Invalid user <name> from <ip> port <port>  (pre-auth rejection)
    _PRE_AUTH_INVALID = re.compile(
        r"(?P<ts>\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: "
        r"Invalid user (?P<user>\S+) "
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    )

    # Accepted password for <name> from <ip>
    _ACCEPTED = re.compile(
        r"(?P<ts>\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: "
        r"Accepted \S+ for (?P<user>\S+) "
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    )

    # Connection closed / disconnected by <ip>
    _DISCONNECTED = re.compile(
        r"(?P<ts>\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: "
        r"(?:Connection closed|Disconnected from) \S+ "
        r"(?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    )

    _PATTERNS = [
        (_INVALID_USER_FAILED, "failed_invalid_user"),
        (_VALID_USER_FAILED,   "failed_valid_user"),
        (_PRE_AUTH_INVALID,    "pre_auth_reject"),
        (_ACCEPTED,            "accepted"),
        (_DISCONNECTED,        "disconnected"),
    ]

    def parse_file(self, log_path: str) -> List[Dict]:
        """Parse all SSH events from a log file."""
        events = []
        with open(log_path, errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                event = self._parse_line(line, lineno)
                if event:
                    events.append(event)
        return events

    def parse_lines(self, lines: List[str]) -> List[Dict]:
        """Parse SSH events from an in-memory list of lines."""
        events = []
        for lineno, line in enumerate(lines, 1):
            event = self._parse_line(line, lineno)
            if event:
                events.append(event)
        return events

    def _parse_line(self, line: str, lineno: int = 0) -> Optional[Dict]:
        for pattern, event_type in self._PATTERNS:
            m = pattern.search(line)
            if m:
                groups = m.groupdict()
                return {
                    "lineno":    lineno,
                    "timestamp": groups.get("ts", ""),
                    "event":     event_type,
                    "username":  groups.get("user", "unknown"),
                    "source_ip": groups.get("ip", "unknown"),
                    "port":      int(groups.get("port", 0)),
                    "raw":       line.strip(),
                }
        return None

    def summary(self, events: List[Dict]) -> Dict:
        """Quick statistics over a parsed event list."""
        from collections import Counter
        event_counts = Counter(e["event"] for e in events)
        ip_counts    = Counter(e["source_ip"] for e in events)
        user_counts  = Counter(e["username"] for e in events)

        return {
            "total_events":       len(events),
            "event_type_counts":  dict(event_counts),
            "top_source_ips":     ip_counts.most_common(10),
            "top_usernames":      user_counts.most_common(10),
            "unique_source_ips":  len(set(e["source_ip"] for e in events)),
            "unique_usernames":   len(set(e["username"] for e in events)),
        }
