"""Shared building blocks used by every WebShield check module.

Each check returns a list of `Finding` objects. The scanner collects them,
sorts them by severity, and prints the report.
"""

from dataclasses import dataclass

# Severity levels (ordered from most to least serious in SEVERITY_ORDER).
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_ORDER = [HIGH, MEDIUM, LOW, INFO]


@dataclass
class Finding:
    """One observation produced by a check."""

    category: str          # e.g. "Headers", "Cookies", "HTTPS"
    title: str             # short one-line summary
    severity: str          # HIGH / MEDIUM / LOW / INFO
    detail: str            # what was observed and why it matters
    remediation: str = ""  # how to fix it (empty for "all good" findings)
