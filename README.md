# SSH User Enumeration: Attack Analysis & Detection Engineering

> **A controlled lab investigation into whether modern OpenSSH leaks username existence
> and how to detect the attempt if it is made.**
> ⚠️ **Legal Notice:** This project was conducted in a fully isolated, self-owned lab
> environment. All findings apply only to that environment. Never test systems you do not
> own or have **explicit written authorisation** to test. Unauthorised computer access is
> illegal in most jurisdictions.

---

## Table of Contents

- [Problem Statement](#-problem-statement)
- [Lab Setup](#-lab-setup)
- [Methodology](#-methodology)
- [What Was Built](#️-what-was-built)
- [Observations & Findings](#-observations--findings)
- [Thought Process](#-thought-process)
- [Security Risks](#-security-risks)
- [Mitigation Strategies](#-mitigation-strategies)
- [Future Enhancements](#-future-enhancements)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [References](#-references)

---

## 🎯 Problem Statement

**User enumeration** — the ability to determine whether a specific username exists on a
remote system without valid credentials. It is a critical first step in the attack chain
leading to account compromise:

```
Reconnaissance → [User Enumeration] → Password Attack → Access
                        ↑
               This project investigates here
```

If an attacker can distinguish "this user exists" from "this user does not exist" byanalysing server responses, they can dramatically reduce the keyspace for subsequent
brute force or credential stuffing attacks.

SSH is a frequent target because it is nearly universally exposed, handles password authentication, and older implementations had measurable timing differences between valid and invalid usernames (CVE-2016-6210).

**This investigation asks two questions:**

1. Does modern OpenSSH on Ubuntu 22.04.5 LTS with default configuration leak username existence
   via response messages, timing, or tool-reported signals?
2. If an attacker makes the attempt regardless, what artefacts does it leave? and how
   reliably can those be detected?

---

## 🖥️ Lab Setup

All testing was performed in a fully isolated host-only virtual network with no internet
exposure.

| Machine  | OS                        | Role                                    | IP               | SSH Version      |
|----------|---------------------------|-----------------------------------------|------------------|------------------|
| Attacker | Kali Linux 2024.1         | Offensive tools, analysis scripts       | 192.168.56.5     | —                |
| Target   | Ubuntu Server 22.04.5 LTS | Running OpenSSH with **default** config | 192.168.56.10    | OpenSSH 8.9p1    |

**Target SSH configuration (`/etc/ssh/sshd_config` defaults):**

```
PasswordAuthentication yes
UsePAM yes                  # Key setting — normalises timing via dummy hash
PermitRootLogin prohibit-password
MaxAuthTries 6
LogLevel INFO
```

`UsePAM yes` is the critical hardening setting. It forces OpenSSH to run a dummy bcrypt computation for non-existent users, matching the timing of a real password check.
This was introduced specifically as a countermeasure to CVE-2016-6210.

---

## 🔬 Methodology

Each attack method was run as an independent trial with a clean log state:

```bash
# Reset log state on target before each trial
sudo truncate -s 0 /var/log/auth.log

# After attack: collect evidence
sudo cp /var/log/auth.log ~/evidence/trial-N-auth.log
```

Evidence collected per trial:
- Tool stdout/stderr (saved verbatim)
- `/var/log/auth.log` from target
- Response timing samples via `time.perf_counter()` in `manual_ssh.py`
- SSH banner grabbed before any auth attempt

### Attack Methods

| Method                | Tool                                 | Wordlist                | Purpose                                         |
|-----------------------|--------------------------------------|-------------------------|-------------------------------------------------|
| Manual SSH            | `ssh` CLI + Paramiko                 | 50 common usernames     | Baseline; inspect raw responses                 |
| Hydra brute force     | `hydra`                              | same 50                 | Automated; leverages Hydra's built-in enum mode |
| Metasploit module     | `auxiliary/scanner/ssh/ssh_enumuser` | same 50                 | Framework's dedicated enumeration module        |
| Banner fingerprinting | custom `BannerFingerprinter`         | N/A                     | No-auth version leak, CVE check                 |
| Timing analysis       | custom `ResponseAnalyzer`            | valid vs invalid subset | Statistical side-channel check                  |

---

## What Was Built

This project goes beyond running tools — it wraps each attack and all detection logic in a structured Python codebase and provides an orchestrator that runs the entire pipeline end-to-end.

### Attack Tools (`src/attack_tools/`)

**`ManualSSHEnumerator`** — Tests each username N times with `paramiko`, recording
precise timing, result type, and SSH banner. Computes mean/std per username. Critically,
it does **not** reuse connections between attempts, ensuring each sample captures the
full server-side processing time.

**`BannerFingerprinter`** — Grabs the SSH banner over a raw TCP socket (no credentials
needed). Parses implementation name, version string, and OS hint. Cross-references
against a local CVE registry. A version like `OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` reveals
the exact server software — potentially enough to identify known vulnerabilities before
any authentication is attempted.

**`HydraAutomation`** — Subprocess wrapper around Hydra. Parses stdout to extract
successful logins, error messages, and Hydra's own enumeration verdict
(`does not support user enumeration`).

**`MetasploitScanner`** — Writes a temporary resource script and drives `msfconsole`
via subprocess. Parses output for hardening detection and any found usernames.

### Detection Tools (`src/detection_tools/`)

**`LogParser`** — Regex-based auth.log parser supporting five SSH event types:
`failed_invalid_user`, `failed_valid_user`, `pre_auth_reject`, `accepted`,
`disconnected`. Returns structured event dicts with timestamp, event type, username,
source IP, and port.

**`ResponseAnalyzer`** — Performs Welch's t-test on timing distributions from valid vs
invalid usernames. Computes timing delta (ms), p-value, Cohen's d effect size, and
a plain-language conclusion. Threshold: delta ≥ 5ms AND p < 0.05 triggers a side-channel
warning.

**`EnumerationDetector`** — Four detection patterns:
- **Rapid user probes**: sliding window — same IP, ≥10 distinct usernames within 60s
- **Wordlist correlation**: match rate between attempted usernames and known attack lists
- **Sequential timing**: coefficient of variation on inter-attempt gaps (low CoV → tool)
- **Distributed probing**: same username from multiple IPs (credential stuffing recon)

**`AlertingSystem`** — Lightweight alert emitter. Generates timestamped JSON alerts to
stdout. Extend with email/SIEM/webhook integrations as needed.

### Orchestrator

**`run_investigation.py`** — CLI driver that runs all four stages in sequence and writes
results to `data/results/`. Run with `--help` for full usage.

```bash
python run_investigation.py \
    -target 192.168.xx.xxxx \
    -usernames data/wordlists/common-usernames-50.txt \
    -log data/sample-logs/auth.log \
    -known-valid root ubuntu \
    -samples 10
```

---

## Observations & Findings

### Finding 1: Response Consistency — The Core Defence

**Hypothesis tested:** Does OpenSSH return a different error message for a non-existent
user than for an existing user with a wrong password?

```bash
# Non-existent user
$ ssh ghost_user_999@192.168.xx.xxxx
Permission denied (publickey,password).

# Existing user, wrong password
$ ssh root@192.168.xx.xxxx
Permission denied (publickey,password).
```

**Result:** Responses are byte-for-byte identical. The protocol leaks nothing.

**Why:** Since OpenSSH 7.3, `UsePAM yes` forces the server to run a dummy `crypt()`
operation for non-existent users, matching both the timing and the error path of a real
failed authentication. The fix was a direct response to CVE-2016-6210.

---

### Finding 2: No Timing Side-Channel Detected

**Hypothesis tested:** Even if error messages match, is there a measurable timing
difference between valid and invalid usernames that could be exploited statistically?

Ten timing samples were collected for each of 50 usernames. Known-valid users (confirmed
from system) were compared against the invalid-user pool.

| Metric                      | Value                               |
|-----------------------------|-------------------------------------|
| Mean timing — invalid users | ~312 ms                             |
| Mean timing — valid users   | ~311 ms                             |
| Delta                       | **~1 ms**                           |
| Welch's t-test p-value      | > 0.40                              |
| Conclusion                  | **No distinguishable side-channel** |

The ~1ms delta is well below the 5ms noise threshold and is not statistically significant
(p >> 0.05). OpenSSH's dummy hash computation is effective.

---

### Finding 3: Hydra Reports No Enumeration Support

Hydra's SSH enumeration mode relies on one of three signals: different error messages,
different timing, or different connection behaviour. With all three normalised, Hydra
explicitly reports:

```
[ERROR] target ssh://192.168.56.10:22/ does not support user enumeration
[STATUS] 50/50 tries completed, 0 valid logins found
```

**Side effect observed:** Despite failing to enumerate, all 50 attempts are logged in
`/var/log/auth.log` with source IP, timestamp, and attempted username. The attacker's
presence is fully visible.

---

### Finding 4: Metasploit Detects Hardening Before Completing Scan

The `auxiliary/scanner/ssh/ssh_enumuser` module checks the OpenSSH version from the
banner before attempting enumeration. Versions ≥ 7.3 with `UsePAM yes` are flagged as
hardened and the module exits early:

```
[*] 192.168.xx.xxxx:22 - SSH - Checking for vulnerability
[*] 192.168.xx.xxxx:22 - SSH - Target is not vulnerable: OpenSSH 8.9p1 (hardened)
```

This is a useful finding: the banner alone communicates the server's defensive posture
to an attacker before any enumeration attempt is made.

---

### Finding 5: Detection is Reliable Even When Enumeration Fails

The key insight from a defender's perspective: **the attack generates noise even when it
does not succeed**. All four detection patterns fired correctly against the collected
auth.log:

| Detection            | Trigger                                       | Severity |
|----------------------|-----------------------------------------------|----------|
| Rapid user probe     | Kali IP probed 50 usernames in <60s           | HIGH     |
| Wordlist correlation | 48/50 attempted names matched wordlist        | HIGH     |
| Sequential timing    | Inter-attempt CoV = 0.04 (tool signature)     | MEDIUM   |
| Banner-only probe    | Pre-auth disconnects before any username sent | LOW      |

---

## 🧠 Thought Process

### Why Manual SSH Enumeration First?

The instinct to start with manual testing was methodologically sound: before trusting
tool output, you need to understand what the raw protocol actually says. Running
`ssh ghost@target` and observing the exact error message tells you whether there is
*anything* to enumerate before investing time in automation.

The first observation — that `Permission denied (publickey,password)` looks identical
regardless of whether the user exists — was the central finding. Everything that followed
was validation of that result.

### Assumptions That Were Made (and Re-examined)

The initial assumption was that Hydra and Metasploit would be *more* capable than manual
testing, so if manual failed, tools might still succeed. This turned out to be wrong in
the expected direction but correct in the *why*: tools don't add capability here because
the protocol itself does not leak the signal. Tools are just automation over the same
protocol.

A second assumption worth examining: the first manual attempt was noticeably slower than
subsequent ones, and the successful-password attempt was fast. This was initially
interpreted as potential timing signal. On reflection, the slowdown was TCP connection
establishment overhead on a fresh network state (ARP resolution, connection setup), not
server-side processing time. Controlling for this — by measuring from
`time.perf_counter()` *after* the TCP handshake, or by discarding the first sample —
would have been more rigorous. The `ManualSSHEnumerator` implementation addresses this
by collecting 10 samples per username and reporting mean/std, which dilutes the first-
sample noise.

### What Changed During the Project

The original scope was narrow: run three tools, document whether they work. The project
evolved in two directions:

**Inward (deeper analysis):** When the initial results were negative, the natural question
became *why* — which led to reading the OpenSSH changelogs, CVE-2016-6210, and the
`UsePAM` implementation. Understanding the mechanism is more valuable than just recording
the outcome.

**Outward (detection pivot):** A negative attack result is still a useful defensive
data point. The pivot to "even though enumeration failed, what did the server see?" led
to the log analysis and detection engineering components, which turned a one-dimensional
tool-running exercise into a two-sided investigation.

### What Would Be Done Differently

The timing measurements were taken over a host-only virtual network, which introduces
less jitter than a real network but also means the results are optimistic. In a real
environment with TCP latency, jitter, and retransmissions, the noise floor would be
higher and the timing analysis would need more samples per username. A more robust
methodology would test over a simulated WAN link (using `tc netem` to introduce
controlled latency and jitter) to see how the conclusions hold under realistic conditions.

---

## Security Risks

Even though enumeration was not successful in this lab, the attack surface and associated
risks are:

**If enumeration *were* possible (e.g., older OpenSSH, `UsePAM no`, custom PAM stack):**
- Attackers could narrow a brute force campaign to confirmed valid usernames only, reducing
  detection risk and increasing efficiency dramatically.
- Combined with password spraying (one common password across all valid usernames), this
  bypasses `MaxAuthTries` per-user lockouts.

**Risks that apply even with enumeration resistance:**
- The SSH banner leaks the exact OpenSSH version and OS. An attacker who sees
  `OpenSSH_8.9p1` can immediately check whether CVE-2024-6387 (regreSSHion) applies,
  before sending a single authentication packet.
- All enumeration attempts are logged with source IP. If log monitoring is absent, a
  slow-burn attack (one attempt per hour) could probe thousands of usernames without
  triggering rate-based alerts.
- `PasswordAuthentication yes` keeps the password-based attack surface open even if
  enumeration is not viable. Post-OSINT credential attacks (using breached password lists
  against OSINT-derived usernames) do not require server-side enumeration at all.

---

## Mitigation Strategies

| Threat                    | Mitigation                                                       | Config Change Required                    |
|---------------------------|------------------------------------------------------------------|-------------------------------------------|
| Timing side-channel       | Ensure `UsePAM yes` (default on Ubuntu)                          | None — already default                    |                  
| Banner version disclosure | `VersionAddendum none` and `DebianBanner no` in `sshd_config`    | Yes                                       |
| Password-based attacks    | `PasswordAuthentication no` — key-only auth                      | Yes                                       |
| Brute force after OSINT   | `fail2ban` with `sshd` jail                                      | Install + configure                       |
| Slow-burn enumeration     | Log shipping to SIEM; alert on >N distinct usernames/IP/hour     | SIEM required                             |
| Root login                | `PermitRootLogin no`                                             | Yes (default is `prohibit-password`)      |
| Pre-auth disconnects      | `MaxStartups 10:30:60` to rate-limit unauthenticated connections | Yes                                       |

**Minimum recommended `sshd_config` additions for a hardened deployment:**

```
PasswordAuthentication no
PermitRootLogin no
MaxAuthTries 3
MaxStartups 10:30:60
VersionAddendum none
LogLevel VERBOSE
```

---

## Future Enhancements

The current project tests one protocol in one configuration. Natural extensions:

**Enumerate other services on the same host.** SMTP (`VRFY`/`EXPN`), LDAP (attribute
queries), HTTP login forms, and SNMP are all common username leak vectors on the same
machine that is hardened at SSH. A comparative study across services would produce a
more complete risk picture.

**Test non-default SSH configurations.** `UsePAM no`, custom PAM modules, Kerberos
authentication backends, and older OpenSSH versions (deployed in embedded systems,
network appliances) may still exhibit timing leaks. Testing the same pipeline against
a deliberately vulnerable configuration would demonstrate the contrast.

**Live detection with inotify.** The current detection runs post-hoc against a copied
log file. A production-grade version would use `inotify` (or `tail -f` + a parser thread)
to detect and alert in near-real-time, within seconds of an enumeration attempt starting.

**Network-level detection.** Auth.log is a host-based artefact. Complement it with
packet-level detection: short-lived TCP connections to port 22 that close before
completing the auth handshake are a signature of banner-only fingerprinting. This could
be implemented as a `Zeek` or `Suricata` rule.

**Jupyter notebooks for statistical reporting.** The timing data collected is amenable
to visualisation — box plots of per-username timing distributions, scatter plots of
attempt frequency over time, heatmaps of source IPs. Notebooks would make the analysis
reproducible and shareable.

---

## Project Structure

```
ssh-enumeration-analysis/
│
├── README.md
├── run_investigation.py        ← Full pipeline orchestrator (start here)
├── requirements.txt
│
├── src/
│   ├── attack_tools/
│   │   ├── __init__.py
│   │   ├── manual_ssh.py           ← Paramiko-based timing probe
│   │   ├── banner_fingerprinter.py ← No-auth banner grab + CVE lookup
│   │   ├── hydra_automation.py     ← Hydra subprocess wrapper
│   │   └── metasploit_scanner.py   ← MSF console automation
│   │
│   └── detection_tools/
│       ├── __init__.py
│       ├── log_parser.py           ← auth.log regex parser
│       ├── response_analyzer.py    ← Welch t-test + Cohen's d
│       ├── pattern_detector.py     ← 4 detection patterns
│       └── alerting_system.py      ← JSON alert emitter
│
├── data/
│   ├── sample-logs/
│   │   ├── auth-baseline.log       ← Normal SSH activity (no attacks)
│   │   ├── auth-hydra-run.log      ← Captured during Hydra trial
│   │   └── auth-msf-run.log        ← Captured during Metasploit trial
│   │
│   ├── wordlists/
│   │   ├── common-usernames-50.txt
│   │   └── common-usernames-100.txt
│   │
│   └── results/                    ← Auto-generated (gitignored)
│       ├── investigation-summary.json
│       ├── manual-enumeration-results.json
│       ├── timing-analysis.json
│       └── detection-report.json
│
├── tests/
│   ├── test_enumeration.py
│   ├── test_detection.py
│   └── test_log_parser.py
│
├── case-study/
│   └── User_Enumeration_attempt_using_manual_SSH.docx
│
└── screenshots/
    ├── manual-ssh-same-response.png
    ├── hydra-no-enumeration-support.png
    ├── metasploit-hardened-detected.png
    ├── auth-log-hydra-evidence.png
    └── detection-alerts-output.png
```

---

## ⚡ Quick Start

```bash
# 1. Clone and install dependencies
git clone https://github.com/<you>/ssh-enumeration-analysis
cd ssh-enumeration-analysis
pip install -r requirements.txt

# 2. Run just the banner fingerprint (no credentials needed)
python -c "
from src.attack_tools.banner_fingerprinter import BannerFingerprinter
r = BannerFingerprinter().grab('192.168.xx.xxxx')
print(r.raw_banner, r.cves)
"

# 3. Run the full investigation pipeline
python run_investigation.py \
    -target 192.168.xx.xxxx \
    -usernames data/wordlists/common-usernames-50.txt \
    -log data/sample-logs/auth-hydra-run.log \
    -known-valid root ubuntu \
    -samples 10

# 4. Analyse a log file only (no live target needed)
python -c "
from src.detection_tools.pattern_detector import EnumerationDetector
d = EnumerationDetector('data/sample-logs/auth-hydra-run.log')
import json; print(json.dumps(d.run_all(), indent=2))
"
```

**Requirements:**

```
paramiko>=3.3.1
scipy>=1.11.0
Hydra and Metasploit must be installed separately (pre-installed on Kali Linux).
```

---

## 📚 References

| Resource                                                                              | Relevance                                       |
|---------------------------------------------------------------------------------------|-------------------------------------------------|
| [CVE-2016-6210](https://nvd.nist.gov/vuln/detail/CVE-2016-6210)                       | The timing side-channel this project tested for |
| [CVE-2024-6387 (regreSSHion)](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)         | Unauthenticated RCE in OpenSSH ≤ 9.7            |
| [OpenSSH sshd_config manual](https://man.openbsd.org/sshd_config)                     | `UsePAM`, `MaxAuthTries`, `VersionAddendum`     |
| [OWASP — User Enumeration](https://owasp.org/www-community/attacks/User_Enumeration)  | General enumeration attack patterns             |
| [RFC 4252 — SSH Authentication Protocol](https://tools.ietf.org/html/rfc4252)         | Protocol spec; defines error message behaviour  |
| [fail2ban documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)           | Rate limiting and IP banning                    |

---

## 🎓 Skills Demonstrated

| Domain                 | Evidence                                                                                                |
|------------------------|---------------------------------------------------------------------------------------------------------|
| SSH Protocol Internals | Understanding of `UsePAM` timing normalisation, CVE-2016-6210 fix, banner information exposure          |
| Offensive Security     | Practical use of Hydra, Metasploit, and custom Paramiko probing in a structured methodology             |
| Statistical Analysis   | Welch's t-test, Cohen's d, coefficient of variation applied to timing data                              |
| Detection Engineering  | Log-based IOC detection across four pattern types; structured alert output                              |
| Python Engineering     | Dataclasses, type hints, subprocess automation, regex parsing, statistical libraries                    |
| Security Research      | Hypothesis → controlled experiment → evidence collection → documented findings → actionable conclusions |

---

**Status:** Complete | **Tested On:** Ubuntu Server 22.04 LTS + OpenSSH 8.9p1 | Kali Linux 2024.1
