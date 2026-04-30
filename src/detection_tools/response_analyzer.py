"""
response_analyzer.py — Statistical Side-Channel Analysis for SSH Timing Data

Determines whether an SSH server leaks user existence via response timing.

Two hypotheses:
  H0 (null):   mean(valid_user_times) == mean(invalid_user_times)   → no side-channel
  H1 (alt):    mean(valid_user_times) != mean(invalid_user_times)   → timing leak exists

Decision rule:
  If |delta_ms| >= TIMING_NOISE_THRESHOLD_MS AND p_value < SIGNIFICANCE_LEVEL → reject H0

CVE reference: CVE-2016-6210 — OpenSSH versions before 7.3 leaked user existence via
measurable timing difference in password hashing (bcrypt cost factor applied only to
existing users). Fixed by applying a dummy hash for non-existent users when UsePAM=yes.
"""

import statistics
from dataclasses import dataclass
from typing import List

try:
    from scipy import stats as _scipy_stats
    _SCIPY_AVAILABLE = True
except ImportError:
    _SCIPY_AVAILABLE = False


TIMING_NOISE_THRESHOLD_MS = 5.0   # Deltas below this are indistinguishable from jitter
SIGNIFICANCE_LEVEL = 0.05          # Standard 95% confidence


@dataclass
class AnalysisResult:
    invalid_user_mean_ms: float
    valid_user_mean_ms: float
    timing_delta_ms: float
    is_distinguishable: bool        # True = potential side-channel
    p_value: float
    confidence_level: str           # "high" | "moderate" | "low" | "undetermined"
    effect_size_cohens_d: float     # Standardised effect size
    conclusion: str
    recommendation: str


class ResponseAnalyzer:
    """
    Compares response timing distributions between valid and invalid SSH usernames.

    Usage:
        analyzer = ResponseAnalyzer()
        result = analyzer.compare_responses(
            invalid_user_times=[0.312, 0.308, 0.315, ...],
            valid_user_times=[0.311, 0.309, 0.314, ...]
        )
        print(result.conclusion)
    """

    def compare_responses(
        self,
        invalid_user_times: List[float],
        valid_user_times: List[float],
    ) -> AnalysisResult:

        if not invalid_user_times or not valid_user_times:
            return AnalysisResult(
                invalid_user_mean_ms=0,
                valid_user_mean_ms=0,
                timing_delta_ms=0,
                is_distinguishable=False,
                p_value=1.0,
                confidence_level="undetermined",
                effect_size_cohens_d=0.0,
                conclusion="Insufficient data for analysis.",
                recommendation="Collect at least 10 samples per username.",
            )

        invalid_mean = statistics.mean(invalid_user_times) * 1000   # → ms
        valid_mean   = statistics.mean(valid_user_times)   * 1000
        delta_ms     = abs(valid_mean - invalid_mean)

        # Welch's t-test (does not assume equal variance — more robust)
        if _SCIPY_AVAILABLE and len(invalid_user_times) > 1 and len(valid_user_times) > 1:
            _, p_value = _scipy_stats.ttest_ind(
                valid_user_times, invalid_user_times, equal_var=False
            )
        else:
            p_value = 1.0   # Can't compute — default to non-significant

        # Cohen's d — standardised effect size
        cohens_d = self._cohens_d(invalid_user_times, valid_user_times)

        is_distinguishable = (delta_ms >= TIMING_NOISE_THRESHOLD_MS) and (p_value < SIGNIFICANCE_LEVEL)

        if p_value < 0.01:
            confidence = "high"
        elif p_value < 0.05:
            confidence = "moderate"
        else:
            confidence = "low"

        if is_distinguishable:
            conclusion = (
                f"Timing side-channel detected — {delta_ms:.2f}ms delta (p={p_value:.4f}). "
                f"Server may be leaking user existence. Investigate UsePAM setting."
            )
            recommendation = (
                "Verify 'UsePAM yes' is set in sshd_config. "
                "If already set, this may indicate a misconfigured PAM stack or "
                "a custom authentication backend without dummy hash compensation."
            )
        else:
            conclusion = (
                f"No timing side-channel detected — {delta_ms:.2f}ms delta is within "
                f"noise threshold ({TIMING_NOISE_THRESHOLD_MS}ms). "
                "OpenSSH response normalisation is effective."
            )
            recommendation = (
                "No immediate action required. Continue monitoring with larger sample sets "
                "if operating in a high-sensitivity environment."
            )

        return AnalysisResult(
            invalid_user_mean_ms=round(invalid_mean, 3),
            valid_user_mean_ms=round(valid_mean, 3),
            timing_delta_ms=round(delta_ms, 3),
            is_distinguishable=is_distinguishable,
            p_value=round(p_value, 4),
            confidence_level=confidence,
            effect_size_cohens_d=round(cohens_d, 4),
            conclusion=conclusion,
            recommendation=recommendation,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cohens_d(a: List[float], b: List[float]) -> float:
        """Pooled-std Cohen's d effect size."""
        if len(a) < 2 or len(b) < 2:
            return 0.0
        mean_diff = abs(statistics.mean(a) - statistics.mean(b))
        pooled_std = (
            ((len(a) - 1) * statistics.variance(a) + (len(b) - 1) * statistics.variance(b))
            / (len(a) + len(b) - 2)
        ) ** 0.5
        return mean_diff / pooled_std if pooled_std > 0 else 0.0

    def summarise_multi_user(
        self, probe_results: list
    ) -> dict:
        """
        Given a list of ProbeResult objects from ManualSSHEnumerator,
        group by result type and report aggregate timing statistics.
        """
        groups: dict = {}
        for r in probe_results:
            groups.setdefault(r.result, []).extend(r.timings_s)

        summary = {}
        for result_type, timings in groups.items():
            if timings:
                summary[result_type] = {
                    "count": len(timings),
                    "mean_ms": round(statistics.mean(timings) * 1000, 3),
                    "std_ms":  round(statistics.stdev(timings) * 1000, 3) if len(timings) > 1 else 0,
                    "min_ms":  round(min(timings) * 1000, 3),
                    "max_ms":  round(max(timings) * 1000, 3),
                }
        return summary
