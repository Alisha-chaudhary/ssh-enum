#!/usr/bin/env python3
"""
run_investigation.py — Full SSH Enumeration Investigation Pipeline
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────
# ANSI color codes
# ─────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

def banner(text, color=CYAN):
    width = 60
    print(f"\n{color}{BOLD}{'═' * width}{RESET}")
    print(f"{color}{BOLD}  {text}{RESET}")
    print(f"{color}{BOLD}{'═' * width}{RESET}\n")

def info(msg):
    print(f"  {BLUE}[*]{RESET} {msg}")

def success(msg):
    print(f"  {GREEN}{BOLD}[✔]{RESET} {msg}")

def warning(msg):
    print(f"  {YELLOW}[!]{RESET} {msg}")

def error(msg):
    print(f"  {RED}[✘]{RESET} {msg}")

def result_line(username, result, mean_s, std_s):
    if result == "auth_failed":
        tag = f"{YELLOW}AUTH_FAILED{RESET}"
    elif result == "success":
        tag = f"{GREEN}{BOLD}SUCCESS ← VALID USER FOUND{RESET}"
    elif result == "error":
        tag = f"{RED}CONNECTION ERROR{RESET}"
    else:
        tag = f"{DIM}{result}{RESET}"

    mean_ms = mean_s * 1000
    print(f"    {WHITE}{username:<20}{RESET}  {tag:<40}  mean={CYAN}{mean_ms:.1f}ms{RESET}  std={DIM}{std_s*1000:.1f}ms{RESET}")


# ─────────────────────────────────────────────
# Suppress default logging noise
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("investigation")


def load_wordlist(path):
    with open(path) as fh:
        return [line.strip() for line in fh if line.strip()]


# ─────────────────────────────────────────────
# Stage 1 — Banner
# ─────────────────────────────────────────────
def stage_1_banner(target_ip, port):
    banner("Stage 1 — SSH Banner Fingerprinting", CYAN)
    from src.attack_tools.banner_fingerprinter import BannerFingerprinter
    fp = BannerFingerprinter(timeout=5)
    r = fp.grab(target_ip, port)

    if r.raw_banner:
        success(f"Banner      : {WHITE}{r.raw_banner}{RESET}")
        info(   f"Version     : {r.implementation} {r.version_string}")
        if r.os_hint:
            info(f"OS Hint     : {r.os_hint}")
        if r.cves:
            for cve in r.cves:
                print(f"\n  {RED}{BOLD}  ⚠  CVE MATCH: {cve['cve']}{RESET}")
                print(f"     {RED}{cve['description']}{RESET}")
                print(f"     Severity : {cve['severity']}")
        else:
            success("No known CVEs matched for this version.")
        for note in r.notes:
            info(note)
    else:
        error("Could not retrieve banner — host may be down or port filtered.")
        warning("Check: is your Ubuntu VM running? Is SSH started?")
        warning(f"Try:   ssh {target_ip} from this terminal to verify connectivity.")

    return {
        "stage": "banner_fingerprinting",
        "target": f"{target_ip}:{port}",
        "raw_banner": r.raw_banner,
        "implementation": r.implementation,
        "version": r.version_string,
        "os_hint": r.os_hint,
        "cves": r.cves,
        "notes": r.notes,
    }


# ─────────────────────────────────────────────
# Stage 2 — Timing Probe
# ─────────────────────────────────────────────
def stage_2_timing_probe(target_ip, port, usernames, password, samples, output_dir):
    banner(f"Stage 2 — Timing Probe  ({len(usernames)} usernames × {samples} samples)", BLUE)
    from src.attack_tools.manual_ssh import ManualSSHEnumerator

    enumerator = ManualSSHEnumerator(target_ip, port)
    results = []
    total = len(usernames)
    success_count = 0
    error_count = 0

    print(f"  {'USERNAME':<20}  {'RESULT':<30}  {'MEAN':>10}  {'STD':>10}")
    print(f"  {'─'*20}  {'─'*30}  {'─'*15}  {'─'*20}")

    for idx, username in enumerate(usernames, 1):
        sys.stdout.write(f"\r  {DIM}Probing {idx}/{total} — {username:<20}{RESET}")
        sys.stdout.flush()
        r = enumerator.test_single_username(username, password, samples=samples)
        results.append(r)

        # Clear the progress line then print the result
        sys.stdout.write("\r" + " " * 70 + "\r")
        result_line(username, r.result, r.mean_s, r.std_s)

        if r.result == "success":
            success_count += 1
        elif r.result == "error":
            error_count += 1

    print()
    # Summary bar
    print(f"  {'─'*60}")
    if success_count > 0:
        print(f"  {GREEN}{BOLD}⚠  {success_count} VALID USERNAME(S) FOUND — enumeration succeeded!{RESET}")
    else:
        success(f"0 successful enumerations out of {total} attempts.")

    if error_count == total:
        error(f"All {total} attempts returned connection errors.")
        warning("The target may be unreachable. Verify the IP and that SSH is running.")

    out_path = os.path.join(output_dir, "manual-enumeration-results.json")
    enumerator.save_results(results, path=out_path)
    info(f"Results saved → {out_path}")
    return results


# ─────────────────────────────────────────────
# Stage 3 — Timing Analysis
# ─────────────────────────────────────────────
def stage_3_timing_analysis(probe_results, known_valid_users, output_dir):
    banner("Stage 3 — Timing Side-Channel Analysis", YELLOW)
    from src.detection_tools.response_analyzer import ResponseAnalyzer

    valid_times, invalid_times = [], []
    for r in probe_results:
        if r.username in known_valid_users:
            valid_times.extend(r.timings_s)
        elif r.result == "auth_failed":
            invalid_times.extend(r.timings_s)

    analyzer = ResponseAnalyzer()
    result = analyzer.compare_responses(invalid_times, valid_times)
    summary = analyzer.summarise_multi_user(probe_results)

    info(f"Valid user samples   : {len(valid_times)}")
    info(f"Invalid user samples : {len(invalid_times)}")
    print()
    info(f"Timing delta         : {CYAN}{result.timing_delta_ms:.3f} ms{RESET}")
    info(f"p-value              : {result.p_value}")
    info(f"Cohen's d            : {result.effect_size_cohens_d}")
    info(f"Confidence           : {result.confidence_level}")
    print()

    if result.is_distinguishable:
        print(f"  {RED}{BOLD}  ⚠  VERDICT: Timing side-channel DETECTED{RESET}")
        print(f"  {RED}  {result.conclusion}{RESET}")
        print(f"  {YELLOW}  Recommendation: {result.recommendation}{RESET}")
    else:
        success(f"VERDICT: No timing side-channel detected.")
        print(f"  {GREEN}  {result.conclusion}{RESET}")
        info(f"Recommendation: {result.recommendation}")

    payload = {
        "stage": "timing_analysis",
        "comparison": {
            "timing_delta_ms": float(result.timing_delta_ms),
            "is_distinguishable": bool(result.is_distinguishable),
            "p_value": float(result.p_value),
            "confidence_level": str(result.confidence_level),
            "effect_size_cohens_d": float(result.effect_size_cohens_d),
            "conclusion": str(result.conclusion),
            "recommendation": str(result.recommendation),
        },
        "per_result_type_summary": summary,
    }
    out_path = os.path.join(output_dir, "timing-analysis.json")
    with open(out_path, "w") as fh:
        json.dump(payload, fh, indent=2)
    info(f"Analysis saved → {out_path}")
    return payload


# ─────────────────────────────────────────────
# Stage 4 — Log Detection
# ─────────────────────────────────────────────
def stage_4_log_detection(log_path, wordlist_path, output_dir):
    banner("Stage 4 — Log-Based Detection", RED)
    from src.detection_tools.pattern_detector import EnumerationDetector
    from src.detection_tools.alerting_system import AlertingSystem

    if not os.path.exists(log_path):
        warning(f"auth.log not found at: {log_path}")
        warning("Skipping detection stage.")
        warning("Copy /var/log/auth.log from Ubuntu VM and place it at the path above.")
        return {}

    detector = EnumerationDetector(log_path)
    report = detector.run_all(wordlist_path=wordlist_path)
    s = report["summary"]

    info(f"Total log events     : {WHITE}{s['total_events']}{RESET}")
    info(f"Unique source IPs    : detected in events")
    print()

    # Rapid probe alerts
    if report["rapid_user_probes"]:
        for alert in report["rapid_user_probes"]:
            sev_color = RED if alert["severity"] == "HIGH" else YELLOW
            print(f"  {sev_color}{BOLD}[{alert['severity']}] Rapid User Probe Detected{RESET}")
            print(f"         Source IP    : {alert['source_ip']}")
            print(f"         Unique users : {alert['unique_usernames']}")
            print(f"         Attempts     : {alert['total_attempts']}")
            print(f"         Window       : {alert['window_seconds']}s")
            print(f"         IOC          : {alert['ioc']}\n")
    else:
        success("No rapid user probe patterns detected.")

    # Wordlist correlation
    wl = report["wordlist_correlation"]
    wl_color = RED if wl["match_rate"] >= 0.5 else YELLOW if wl["match_rate"] >= 0.2 else GREEN
    print(f"  {wl_color}[WORDLIST] Match rate: {wl['match_rate']*100:.1f}%  ({wl['match_count']}/{wl['attempted_usernames']} usernames){RESET}")
    print(f"           Severity  : {wl['severity']}")
    print(f"           Conclusion: {wl['conclusion']}\n")

    # Distributed probing
    if report["distributed_probing"]:
        for alert in report["distributed_probing"]:
            print(f"  {RED}{BOLD}[HIGH] Distributed Probe — username '{alert['username']}' from {alert['ip_count']} IPs{RESET}")
    else:
        success("No distributed probing patterns detected.")

    # Overall verdict
    print()
    high = s["high_severity_alerts"]
    if high > 0:
        print(f"  {RED}{BOLD}{'═'*50}{RESET}")
        print(f"  {RED}{BOLD}  ⚠  {high} HIGH SEVERITY ALERT(S) RAISED{RESET}")
        print(f"  {RED}{BOLD}{'═'*50}{RESET}")
        alerter = AlertingSystem()
        alerter.generate_alert({"trigger": "high_severity_ssh_enumeration_detected", "details": s})
    else:
        print(f"  {GREEN}{BOLD}{'═'*50}{RESET}")
        success("Investigation complete — no high severity alerts.")
        print(f"  {GREEN}{BOLD}{'═'*50}{RESET}")

    out_path = os.path.join(output_dir, "detection-report.json")
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2)
    info(f"Detection report → {out_path}")
    return report


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SSH Enumeration Investigation Pipeline")
    parser.add_argument("-target",       required=True)
    parser.add_argument("-port",         type=int, default=22)
    parser.add_argument("-usernames",    default="data/wordlists/common-usernames-50.txt")
    parser.add_argument("-password",     default="wrongpassword123")
    parser.add_argument("-samples",      type=int, default=10)
    parser.add_argument("-log",          default="data/sample-logs/auth.log")
    parser.add_argument("-known-valid",  nargs="*", default=[])
    parser.add_argument("-output",       default="data/results/")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    usernames = load_wordlist(args.usernames)

    # Header
    print(f"\n{CYAN}{BOLD}{'═'*60}{RESET}")
    print(f"{CYAN}{BOLD}   SSH USER ENUMERATION INVESTIGATION{RESET}")
    print(f"{CYAN}{BOLD}{'═'*60}{RESET}")
    info(f"Target     : {WHITE}{args.target}:{args.port}{RESET}")
    info(f"Wordlist   : {args.usernames}  ({len(usernames)} entries)")
    info(f"Auth log   : {args.log}")
    info(f"Started at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    investigation = {
        "metadata": {
            "target": args.target,
            "port": args.port,
            "started_at": datetime.now().isoformat(),
            "wordlist": args.usernames,
            "usernames_tested": len(usernames),
        },
        "stages": {}
    }

    investigation["stages"]["banner"]    = stage_1_banner(args.target, args.port)
    probe_results                         = stage_2_timing_probe(
        args.target, args.port, usernames, args.password, args.samples, args.output)
    investigation["stages"]["timing"]    = stage_3_timing_analysis(
        probe_results, args.known_valid, args.output)
    investigation["stages"]["detection"] = stage_4_log_detection(
        args.log, args.usernames, args.output)

    investigation["metadata"]["completed_at"] = datetime.now().isoformat()

    summary_path = os.path.join(args.output, "investigation-summary.json")
    with open(summary_path, "w") as fh:
        from dataclasses import asdict
        investigation["stages"]["probe_results"] = [asdict(r) for r in probe_results]
        json.dump(investigation, fh, indent=2)

    banner("Investigation Complete", GREEN)
    info(f"All results saved in: {WHITE}{args.output}{RESET}")
    info(f"Summary file        : {WHITE}{summary_path}{RESET}")


if __name__ == "__main__":
    main()
