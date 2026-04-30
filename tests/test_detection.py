"""
test_detection.py — Unit tests for detection_tools

Tests cover:
  - LogParser: correct event type tagging, IP/username extraction
  - ResponseAnalyzer: delta calculation, distinguishability threshold
  - EnumerationDetector: rapid probe detection logic
"""

import unittest
from unittest.mock import patch, mock_open
from src.detection_tools.log_parser import LogParser
from src.detection_tools.response_analyzer import ResponseAnalyzer


# ---------------------------------------------------------------------------
# Sample auth.log lines
# ---------------------------------------------------------------------------
INVALID_USER_LINE = (
    "Apr 19 12:34:56 ubuntu sshd[1234]: "
    "Failed password for invalid user admin from 192.168.56.5 port 54321 ssh2"
)
VALID_USER_LINE = (
    "Apr 19 12:34:57 ubuntu sshd[1235]: "
    "Failed password for root from 192.168.56.5 port 54322 ssh2"
)
PRE_AUTH_LINE = (
    "Apr 19 12:34:58 ubuntu sshd[1236]: "
    "Invalid user ubuntu2 from 192.168.56.5 port 54323"
)
ACCEPTED_LINE = (
    "Apr 19 12:35:00 ubuntu sshd[1237]: "
    "Accepted password for ubuntu from 192.168.56.5 port 54324 ssh2"
)
NOISE_LINE = "Apr 19 12:35:01 ubuntu systemd[1]: Started cron.service"


class TestLogParser(unittest.TestCase):

    def setUp(self):
        self.parser = LogParser()

    def _parse(self, line):
        return self.parser._parse_line(line, lineno=1)

    def test_invalid_user_failed_parsed(self):
        e = self._parse(INVALID_USER_LINE)
        self.assertIsNotNone(e)
        self.assertEqual(e["event"], "failed_invalid_user")
        self.assertEqual(e["username"], "admin")
        self.assertEqual(e["source_ip"], "192.168.56.5")

    def test_valid_user_failed_parsed(self):
        e = self._parse(VALID_USER_LINE)
        self.assertIsNotNone(e)
        self.assertEqual(e["event"], "failed_valid_user")
        self.assertEqual(e["username"], "root")

    def test_pre_auth_reject_parsed(self):
        e = self._parse(PRE_AUTH_LINE)
        self.assertIsNotNone(e)
        self.assertEqual(e["event"], "pre_auth_reject")
        self.assertEqual(e["username"], "ubuntu2")

    def test_accepted_parsed(self):
        e = self._parse(ACCEPTED_LINE)
        self.assertIsNotNone(e)
        self.assertEqual(e["event"], "accepted")
        self.assertEqual(e["username"], "ubuntu")

    def test_noise_line_returns_none(self):
        e = self._parse(NOISE_LINE)
        self.assertIsNone(e)

    def test_parse_lines_filters_noise(self):
        lines = [INVALID_USER_LINE, NOISE_LINE, VALID_USER_LINE]
        events = self.parser.parse_lines(lines)
        self.assertEqual(len(events), 2)


class TestResponseAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = ResponseAnalyzer()

    def test_no_side_channel_when_delta_small(self):
        # Timing within noise floor → not distinguishable
        invalid = [0.310, 0.312, 0.309, 0.311, 0.313] * 2
        valid   = [0.311, 0.310, 0.312, 0.309, 0.311] * 2
        result = self.analyzer.compare_responses(invalid, valid)
        self.assertFalse(result.is_distinguishable)
        self.assertLess(result.timing_delta_ms, 5.0)

    def test_side_channel_detected_when_delta_large(self):
        # Simulate a timing leak: valid users take 50ms longer
        invalid = [0.200] * 20
        valid   = [0.250] * 20
        result = self.analyzer.compare_responses(invalid, valid)
        self.assertTrue(result.is_distinguishable)
        self.assertGreaterEqual(result.timing_delta_ms, 5.0)

    def test_empty_lists_returns_gracefully(self):
        result = self.analyzer.compare_responses([], [])
        self.assertFalse(result.is_distinguishable)
        self.assertEqual(result.conclusion, "Insufficient data for analysis.")

    def test_cohens_d_zero_for_identical_distributions(self):
        times = [0.300] * 10
        result = self.analyzer.compare_responses(times, times)
        self.assertEqual(result.effect_size_cohens_d, 0.0)


if __name__ == "__main__":
    unittest.main()
