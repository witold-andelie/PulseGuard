"""Scanner adapters (S1: Semgrep runner, Trivy report loader, normaliser)."""

from pulseguard.scanners.normalize import fingerprint_for, normalize, normalize_trivy
from pulseguard.scanners.semgrep import DataflowTrace, SemgrepResult, SemgrepRunner, TraceLine
from pulseguard.scanners.trivy import TrivyReportLoader, TrivyVulnerability

__all__ = [
    "DataflowTrace",
    "SemgrepResult",
    "SemgrepRunner",
    "TraceLine",
    "TrivyReportLoader",
    "TrivyVulnerability",
    "fingerprint_for",
    "normalize",
    "normalize_trivy",
]
