#!/usr/bin/env python3
"""WebShield - a small passive web security scanner.

Usage:
    python scanner.py https://example.com
    python scanner.py https://example.com --timeout 5 --save

This file is the CLI entry point. It:
  1. validates the URL,
  2. makes one GET request (following redirects),
  3. hands the response to the check modules in checks/,
  4. prints (and optionally saves) a report.

Exit codes: 0 = scan finished, no HIGH findings
            1 = scan finished, at least one HIGH finding
            2 = scan could not run (bad URL, connection problem, ...)
"""

import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from textwrap import fill
from urllib.parse import urlsplit

import requests

from checks import SEVERITY_ORDER, Finding, HIGH, MEDIUM, LOW, INFO
from checks.cookies import check_cookies
from checks.headers import check_security_headers
from checks.information import check_information_disclosure
from checks.transport import check_http_redirect, check_https

REQUEST_HEADERS = {"User-Agent": "WebShield/1.0 (passive security scanner)"}
REPORTS_DIR = Path(__file__).parent / "reports"

REPORT_WIDTH = 78
COLORS = {HIGH: "\033[91m", MEDIUM: "\033[93m", LOW: "\033[94m", INFO: "\033[90m"}
RESET = "\033[0m"


class ScanError(Exception):
    """Raised for problems that stop the scan; the message is shown to the user."""


# --------------------------------------------------------------------------
# Input handling and HTTP request
# --------------------------------------------------------------------------

def normalize_url(raw_url):
    """Validate the user's URL and return it. Assumes https:// if no scheme is given."""
    raw_url = raw_url.strip()
    if not raw_url or re.search(r"\s", raw_url):
        raise ScanError("Invalid URL: it is empty or contains spaces.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    try:
        parts = urlsplit(raw_url)
        parts.port  # accessing .port raises ValueError for a malformed port
    except ValueError:
        raise ScanError(f"Invalid URL: {raw_url}")

    if parts.scheme not in ("http", "https"):
        raise ScanError("Only http:// and https:// URLs are supported.")
    if not parts.hostname:
        raise ScanError(f"Invalid URL (no hostname found): {raw_url}")
    return raw_url


def fetch(url, timeout):
    """Make the single GET request and translate requests' exceptions into friendly errors.

    Order matters: SSLError and ConnectTimeout are subclasses of ConnectionError,
    so the more specific exceptions must be caught first.
    """
    try:
        return requests.get(url, headers=REQUEST_HEADERS, timeout=timeout, allow_redirects=True)
    except requests.exceptions.SSLError as exc:
        raise ScanError("SSL error: the certificate could not be verified (it may be expired, "
                        f"self-signed, or issued for another hostname). Details: {exc.__class__.__name__}")
    except requests.exceptions.Timeout:
        raise ScanError(f"Timed out after {timeout} seconds waiting for the server.")
    except requests.exceptions.ConnectionError:
        raise ScanError("Connection failed: could not reach the host "
                        "(DNS failure, refused connection, or no network).")
    except requests.exceptions.TooManyRedirects:
        raise ScanError("Too many redirects: the site appears to be stuck in a redirect loop.")
    except requests.exceptions.RequestException as exc:
        raise ScanError(f"Request failed: {exc}")


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def check_response(response, target_url):
    """Notes about the response itself: error status codes and cross-host redirects."""
    findings = []
    if response.status_code >= 400:
        findings.append(Finding(
            "Response", f"Server returned HTTP {response.status_code}", INFO,
            "Headers and cookies were analysed from this error response and may differ "
            "from those of a normal page. A firewall or login wall may be answering instead of the app."))

    if urlsplit(response.url).hostname != urlsplit(target_url).hostname:
        findings.append(Finding(
            "Response", "Request was redirected to a different host", INFO,
            f"Results describe {urlsplit(response.url).hostname}, not the host you entered."))
    return findings


def collect_findings(target_url, response, timeout):
    """Run every check module and return all findings, most severe first."""
    is_https = urlsplit(response.url).scheme == "https"

    findings = []
    findings += check_response(response, target_url)
    findings += check_https(response.url)
    findings += check_http_redirect(target_url, timeout, REQUEST_HEADERS)
    findings += check_security_headers(response.headers, is_https)
    findings += check_cookies(response)
    findings += check_information_disclosure(response.headers)

    # sorted() is stable, so findings keep their check order within a severity.
    return sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def build_report(target_url, response, findings, color=False):
    """Return the report as a string. `color=True` adds ANSI colours for terminals."""
    indent = " " * 9

    def tag(severity):
        label = f"[{severity}]".ljust(9)
        return f"{COLORS[severity]}{label}{RESET}" if color else label

    lines = [
        "=" * REPORT_WIDTH,
        " WebShield Security Report",
        "=" * REPORT_WIDTH,
        f"Target URL  : {target_url}",
        f"HTTP status : {response.status_code} {response.reason or ''}".rstrip(),
        f"Final URL   : {response.url}",
        f"Redirects   : {len(response.history)}",
        f"Scanned at  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "Findings",
        "-" * REPORT_WIDTH,
    ]

    for f in findings:
        lines.append(f"{tag(f.severity)}{f.title}")
        lines.append(fill(f"[{f.category}] {f.detail}", REPORT_WIDTH,
                          initial_indent=indent, subsequent_indent=indent))
        if f.remediation:
            lines.append(fill(f"Fix: {f.remediation}", REPORT_WIDTH,
                              initial_indent=indent, subsequent_indent=indent + "     "))
        lines.append("")

    lines += ["Summary", "-" * REPORT_WIDTH]
    for severity in SEVERITY_ORDER:
        count = sum(1 for f in findings if f.severity == severity)
        lines.append(f"  {severity:<7}: {count}")
    lines.append(f"  {'TOTAL':<7}: {len(findings)}")
    lines.append("=" * REPORT_WIDTH)
    return "\n".join(lines)


def save_report(text, target_url):
    """Write the plain-text report into reports/ and return its path."""
    REPORTS_DIR.mkdir(exist_ok=True)
    host = re.sub(r"[^A-Za-z0-9.-]", "_", urlsplit(target_url).hostname or "target")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"webshield_{host}_{stamp}.txt"
    path.write_text(text + "\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="WebShield: passive web security checks (HTTPS, headers, cookies, info disclosure).",
        epilog="Only scan systems you own or have explicit permission to test.")
    parser.add_argument("url", help="target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=float, default=10,
                        help="seconds to wait for each request (default: 10)")
    parser.add_argument("--save", action="store_true",
                        help="also save a plain-text report in the reports/ folder")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.timeout <= 0:
        print("Error: timeout must be a positive number.", file=sys.stderr)
        return 2

    try:
        target = normalize_url(args.url)
        response = fetch(target, args.timeout)
    except ScanError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    findings = collect_findings(target, response, args.timeout)

    use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(build_report(target, response, findings, color=use_color))

    if args.save:
        path = save_report(build_report(target, response, findings), target)
        print(f"\nReport saved to {path}")

    return 1 if any(f.severity == HIGH for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
