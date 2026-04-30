"""
banner_fingerprinter.py — SSH Banner Analysis & CVE Lookup

The SSH banner (version string) is transmitted before any authentication.
It is not sensitive but reveals:
  - SSH implementation (OpenSSH, Dropbear, libssh, ...)
  - Version number → known CVEs
  - OS/distro hints (e.g. "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

This module grabs the banner over a raw TCP socket (no credentials needed)
and cross-references it against a local CVE registry for quick triage.
"""

import re
import socket
import logging
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Minimal local CVE registry — extend this as needed
# ---------------------------------------------------------------------------
# Each entry: (min_version_tuple, max_version_tuple_exclusive, cve_id, description)
# Version tuple format: (major, minor, patch) — patch defaults to 0

_CVE_REGISTRY = [
    # CVE-2016-6210: timing oracle — user enumeration via bcrypt cost
    ((0, 0, 0), (7, 3, 0), "CVE-2016-6210",
     "Timing side-channel reveals user existence (bcrypt cost not applied to dummy hash)"),
    # CVE-2023-38408: Remote code execution via ssh-agent forwarding
    ((0, 0, 0), (9, 3, 0), "CVE-2023-38408",
     "ssh-agent remote code execution via PKCS#11 provider loading"),
    # CVE-2024-6387: regreSSHion — unauthenticated RCE (race condition in signal handler)
    ((8, 5, 0), (9, 8, 0), "CVE-2024-6387",
     "regreSSHion: unauthenticated RCE via race condition in sshd signal handler"),
]


@dataclass
class BannerResult:
    target: str
    raw_banner: Optional[str]
    implementation: Optional[str]    # "OpenSSH" | "Dropbear" | "libssh" | ...
    version_string: Optional[str]    # "8.9p1"
    version_tuple: Optional[tuple]   # (8, 9, 0)
    os_hint: Optional[str]           # "Ubuntu-3ubuntu0.6"
    cves: List[dict] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


class BannerFingerprinter:
    """
    Grab the SSH banner and analyse it for version and CVE exposure.

    Does NOT require credentials — the banner is sent before auth.
    """

    BANNER_RE = re.compile(
        r"SSH-2\.0-"
        r"(?P<impl>[A-Za-z]+)"              # e.g. OpenSSH
        r"[_\-]?"
        r"(?P<ver>[0-9]+\.[0-9]+(?:p[0-9]+)?)"  # e.g. 8.9p1
        r"(?:\s+(?P<os>.+))?"               # e.g. Ubuntu-3ubuntu0.6
    )
    VERSION_NUM_RE = re.compile(r"(\d+)\.(\d+)(?:p(\d+))?")

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def grab(self, host: str, port: int = 22) -> BannerResult:
        target = f"{host}:{port}"
        raw_banner = self._fetch_banner(host, port)

        if raw_banner is None:
            return BannerResult(target=target, raw_banner=None,
                                implementation=None, version_string=None,
                                version_tuple=None, os_hint=None,
                                notes=["Could not retrieve banner — host may be down or filtered"])

        m = self.BANNER_RE.search(raw_banner)
        if not m:
            return BannerResult(target=target, raw_banner=raw_banner,
                                implementation=None, version_string=None,
                                version_tuple=None, os_hint=None,
                                notes=["Banner format not recognised"])

        impl   = m.group("impl")
        ver_s  = m.group("ver")
        os_h   = m.group("os")
        v_tup  = self._parse_version(ver_s)

        cves   = self._check_cves(impl, v_tup) if v_tup else []
        notes  = []
        if os_h:
            notes.append(f"OS/distro hint in banner: '{os_h}' — consider suppressing with 'DebianBanner no'")
        if not cves:
            notes.append(f"No known CVEs matched for {impl} {ver_s}")

        return BannerResult(
            target=target,
            raw_banner=raw_banner.strip(),
            implementation=impl,
            version_string=ver_s,
            version_tuple=v_tup,
            os_hint=os_h,
            cves=cves,
            notes=notes,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fetch_banner(self, host: str, port: int) -> Optional[str]:
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                banner = s.recv(256).decode("ascii", errors="replace")
                return banner
        except Exception as exc:
            log.warning("Banner fetch failed for %s:%d — %s", host, port, exc)
            return None

    def _parse_version(self, ver_str: str) -> Optional[tuple]:
        m = self.VERSION_NUM_RE.search(ver_str)
        if not m:
            return None
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3)) if m.group(3) else 0
        return (major, minor, patch)

    def _check_cves(self, impl: str, version: tuple) -> List[dict]:
        if impl.lower() != "openssh":
            return []   # Registry is OpenSSH-only for now
        found = []
        for (min_v, max_v, cve_id, desc) in _CVE_REGISTRY:
            if min_v <= version < max_v:
                found.append({
                    "cve": cve_id,
                    "description": desc,
                    "affected_range": f">={'.'.join(map(str, min_v))} <{'.'.join(map(str, max_v))}",
                    "severity": "CRITICAL" if "RCE" in desc or "regreSSHion" in desc else "MEDIUM",
                })
        return found
