"""
pattern_detector.py — SSH Enumeration Pattern Detection

Analyses parsed auth.log events to identify enumeration behaviour:

  1. Rapid user probes    — single IP cycling through many usernames in a short window
  2. Wordlist matching    — attempted usernames correlate with known attack wordlists
  3. Sequential timing    — attempts are evenly spaced (tooling signature, not human)
  4. Distributed probing  — same username hit from multiple IPs (credential stuffing recon)

Each detection returns a structured dict suitable for forwarding to the AlertingSystem.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any


def _parse_dt(ts: str) -> datetime:
    """
    Parse timestamps in the form 'Apr 19 12:34:56' (no year — assume current year).
    Falls back gracefully if format is unexpected.
    """
    try:
        return datetime.strptime(ts, "%b %d %H:%M:%S").replace(year=datetime.now().year)
    except ValueError:
        return datetime.min


class EnumerationDetector:
    """
    Wraps a list of parsed auth.log events and provides detection methods.

    Events are dicts with keys: timestamp, event, username, source_ip, raw
    """

    def __init__(self, log_path: str):
        from src.detection_tools.log_parser import LogParser
        self.events: List[Dict] = LogParser().parse_file(log_path)
        self.log_path = log_path

    # ------------------------------------------------------------------
    # Detection 1: Rapid username cycling from one IP
    # ------------------------------------------------------------------

    def find_rapid_user_probes(
        self,
        window_seconds: int = 60,
        threshold: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Flag IPs that probe >= threshold distinct usernames within window_seconds.
        Returns list of alert dicts sorted by unique_usernames descending.
        """
        ip_events: Dict[str, list] = defaultdict(list)
        for e in self.events:
            ip_events[e["source_ip"]].append(e)

        alerts = []
        for ip, evts in ip_events.items():
            evts_sorted = sorted(evts, key=lambda e: _parse_dt(e["timestamp"]))
            # Sliding window
            for i, start_evt in enumerate(evts_sorted):
                start_dt = _parse_dt(start_evt["timestamp"])
                window_end = start_dt + timedelta(seconds=window_seconds)
                window_evts = [
                    e for e in evts_sorted[i:]
                    if _parse_dt(e["timestamp"]) <= window_end
                ]
                unique_users = {e["username"] for e in window_evts}
                if len(unique_users) >= threshold:
                    alerts.append({
                        "type": "rapid_user_probe",
                        "source_ip": ip,
                        "window_seconds": window_seconds,
                        "unique_usernames": len(unique_users),
                        "total_attempts": len(window_evts),
                        "usernames_sampled": sorted(unique_users)[:20],
                        "window_start": start_evt["timestamp"],
                        "severity": "HIGH" if len(unique_users) >= threshold * 2 else "MEDIUM",
                        "ioc": f"IP {ip} probed {len(unique_users)} distinct usernames in {window_seconds}s",
                    })
                    break   # One alert per IP is enough

        return sorted(alerts, key=lambda a: a["unique_usernames"], reverse=True)

    # ------------------------------------------------------------------
    # Detection 2: Wordlist correlation
    # ------------------------------------------------------------------

    def find_wordlist_patterns(
        self, wordlist_path: str
    ) -> Dict[str, Any]:
        """
        Check whether attempted usernames appear in a known attack wordlist.
        High match rate → likely automated tooling with common credential list.
        """
        with open(wordlist_path) as fh:
            known = {line.strip().lower() for line in fh if line.strip()}

        attempted = {e["username"].lower() for e in self.events if e["username"] != "unknown"}
        matches = attempted & known
        rate = len(matches) / max(len(attempted), 1)

        return {
            "type": "wordlist_correlation",
            "wordlist": wordlist_path,
            "attempted_usernames": len(attempted),
            "wordlist_size": len(known),
            "match_count": len(matches),
            "match_rate": round(rate, 4),
            "matched_usernames": sorted(matches),
            "severity": "HIGH" if rate >= 0.5 else "MEDIUM" if rate >= 0.2 else "LOW",
            "conclusion": (
                "Strong wordlist correlation — likely automated attack"
                if rate >= 0.5
                else "Partial wordlist match — possible low-signal attack or coincidence"
                if rate >= 0.2
                else "Low wordlist correlation — may be opportunistic or targeted"
            ),
        }

    # ------------------------------------------------------------------
    # Detection 3: Sequential / evenly-spaced attempts (tool fingerprint)
    # ------------------------------------------------------------------

    def find_sequential_timing(
        self,
        ip: str,
        jitter_tolerance_s: float = 0.5,
    ) -> Dict[str, Any]:
        """
        Human attackers are irregular; tools produce evenly-spaced attempts.
        Compute coefficient of variation (std/mean) of inter-attempt gaps.
        Low CoV → mechanical/automated pacing.
        """
        ip_events = sorted(
            [e for e in self.events if e["source_ip"] == ip],
            key=lambda e: _parse_dt(e["timestamp"]),
        )
        if len(ip_events) < 3:
            return {"type": "sequential_timing", "source_ip": ip, "result": "insufficient_data"}

        gaps = []
        for i in range(1, len(ip_events)):
            dt1 = _parse_dt(ip_events[i - 1]["timestamp"])
            dt2 = _parse_dt(ip_events[i]["timestamp"])
            gap = (dt2 - dt1).total_seconds()
            if gap >= 0:
                gaps.append(gap)

        if not gaps:
            return {"type": "sequential_timing", "source_ip": ip, "result": "no_gap_data"}

        import statistics as _s
        mean_gap = _s.mean(gaps)
        std_gap  = _s.stdev(gaps) if len(gaps) > 1 else 0.0
        cov = std_gap / mean_gap if mean_gap > 0 else 0.0

        return {
            "type": "sequential_timing",
            "source_ip": ip,
            "attempt_count": len(ip_events),
            "mean_gap_s": round(mean_gap, 3),
            "std_gap_s":  round(std_gap, 3),
            "coefficient_of_variation": round(cov, 4),
            "is_automated": cov < 0.3,   # Very consistent spacing → tool-generated
            "severity": "MEDIUM",
            "conclusion": (
                "Low timing variance suggests automated tooling"
                if cov < 0.3
                else "Irregular timing — may indicate manual or slow-burn attack"
            ),
        }

    # ------------------------------------------------------------------
    # Detection 4: Distributed probing of same username
    # ------------------------------------------------------------------

    def find_distributed_probing(
        self, threshold_ips: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Credential stuffing recon: same username probed from multiple IPs.
        Indicates the username was obtained via OSINT and being tested from a botnet.
        """
        user_ips: Dict[str, set] = defaultdict(set)
        for e in self.events:
            if e["username"] != "unknown":
                user_ips[e["username"]].add(e["source_ip"])

        alerts = []
        for username, ips in user_ips.items():
            if len(ips) >= threshold_ips:
                alerts.append({
                    "type": "distributed_probe",
                    "username": username,
                    "source_ips": sorted(ips),
                    "ip_count": len(ips),
                    "severity": "HIGH",
                    "ioc": f"Username '{username}' probed from {len(ips)} distinct IPs",
                })

        return sorted(alerts, key=lambda a: a["ip_count"], reverse=True)

    # ------------------------------------------------------------------
    # Convenience: run all detections
    # ------------------------------------------------------------------

    def run_all(
        self,
        wordlist_path: str = "data/wordlists/common-usernames-50.txt",
        probe_window: int = 60,
        probe_threshold: int = 10,
    ) -> Dict[str, Any]:
        rapid   = self.find_rapid_user_probes(probe_window, probe_threshold)
        wl      = self.find_wordlist_patterns(wordlist_path)
        distrib = self.find_distributed_probing()
        high_alerts = [a for a in rapid + distrib if a.get("severity") == "HIGH"]

        return {
            "summary": {
                "total_events": len(self.events),
                "high_severity_alerts": len(high_alerts),
                "rapid_probe_alerts": len(rapid),
                "distributed_probe_alerts": len(distrib),
                "wordlist_match_rate": wl["match_rate"],
            },
            "rapid_user_probes": rapid,
            "wordlist_correlation": wl,
            "distributed_probing": distrib,
        }
