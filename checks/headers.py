"""Security-header checks.

Each helper looks at one header and returns a list of Findings.
`headers` is the `response.headers` object from `requests`, which is
case-insensitive, so headers.get("x-frame-options") also works.
"""

import re

from . import Finding, MEDIUM, LOW, INFO

CATEGORY = "Headers"

# HSTS max-age below this (180 days, in seconds) is considered too short.
MIN_HSTS_MAX_AGE = 15_552_000


def check_security_headers(headers, is_https):
    """Run every header check and combine the results."""
    findings = []
    findings += _check_hsts(headers, is_https)
    findings += _check_csp(headers)
    findings += _check_x_frame_options(headers)
    findings += _check_x_content_type_options(headers)
    findings += _check_referrer_policy(headers)
    return findings


def _check_hsts(headers, is_https):
    name = "Strict-Transport-Security"
    if not is_https:
        # Browsers ignore HSTS received over plain HTTP, so there is nothing to judge.
        return [Finding(CATEGORY, f"{name} not evaluated", INFO,
                        "HSTS is only honoured when delivered over HTTPS.")]

    value = headers.get(name)
    if value is None:
        return [Finding(CATEGORY, f"Missing {name}", MEDIUM,
                        "Browsers are not told to always use HTTPS for this site, "
                        "so SSL-stripping attacks remain possible.",
                        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")]

    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match or int(match.group(1)) < MIN_HSTS_MAX_AGE:
        return [Finding(CATEGORY, f"{name} max-age is missing or too short", LOW,
                        f"Value is '{value}'. A short lifetime weakens the protection.",
                        "Use max-age of at least 15552000 (180 days); 31536000 is common.")]

    return [Finding(CATEGORY, f"{name} is set", INFO, f"Value: {value}")]


def _check_csp(headers):
    name = "Content-Security-Policy"
    value = headers.get(name)
    if value is None:
        return [Finding(CATEGORY, f"Missing {name}", MEDIUM,
                        "No browser-enforced limit on where scripts and other content may "
                        "load from, which makes cross-site scripting (XSS) easier to exploit.",
                        "Define a policy, e.g. Content-Security-Policy: default-src 'self'")]

    weak = [kw for kw in ("'unsafe-inline'", "'unsafe-eval'") if kw in value]
    if weak:
        return [Finding(CATEGORY, f"{name} allows {', '.join(weak)}", LOW,
                        "These keywords re-enable the script behaviour CSP is meant to restrict.",
                        "Remove unsafe keywords; use nonces or hashes for inline scripts.")]

    return [Finding(CATEGORY, f"{name} is set", INFO, "A policy is present.")]


def _check_x_frame_options(headers):
    name = "X-Frame-Options"
    value = headers.get(name)
    csp = headers.get("Content-Security-Policy", "").lower()

    if value is not None and value.strip().upper() in ("DENY", "SAMEORIGIN"):
        return [Finding(CATEGORY, f"{name} is set", INFO, f"Value: {value}")]
    if "frame-ancestors" in csp:
        # CSP frame-ancestors is the modern replacement for X-Frame-Options.
        return [Finding(CATEGORY, "Clickjacking protection via CSP frame-ancestors", INFO,
                        "The CSP frame-ancestors directive controls who may embed this page.")]
    if value is None:
        return [Finding(CATEGORY, f"Missing {name}", MEDIUM,
                        "The page can be embedded in another site's frame, enabling "
                        "clickjacking (tricking users into clicking hidden UI).",
                        "Add: X-Frame-Options: DENY (or use CSP frame-ancestors 'none').")]
    return [Finding(CATEGORY, f"{name} has an unrecognised value", LOW,
                    f"Value is '{value}'. Only DENY and SAMEORIGIN are reliably supported.",
                    "Use DENY or SAMEORIGIN.")]


def _check_x_content_type_options(headers):
    name = "X-Content-Type-Options"
    value = headers.get(name)
    if value is not None and value.strip().lower() == "nosniff":
        return [Finding(CATEGORY, f"{name} is set", INFO, "Value: nosniff")]
    if value is None:
        return [Finding(CATEGORY, f"Missing {name}", LOW,
                        "Browsers may guess ('sniff') content types, which can turn an "
                        "uploaded file into executable script.",
                        "Add: X-Content-Type-Options: nosniff")]
    return [Finding(CATEGORY, f"{name} has an unexpected value", LOW,
                    f"Value is '{value}'; the only valid value is 'nosniff'.",
                    "Set the value to nosniff.")]


def _check_referrer_policy(headers):
    name = "Referrer-Policy"
    value = headers.get(name)
    if value is None:
        return [Finding(CATEGORY, f"Missing {name}", LOW,
                        "Full URLs (which may contain tokens or IDs) can leak to other "
                        "sites through the Referer header.",
                        "Add: Referrer-Policy: strict-origin-when-cross-origin")]

    # If several policies are listed, browsers use the last one they understand.
    policy = value.split(",")[-1].strip().lower()
    if policy in ("unsafe-url", "no-referrer-when-downgrade"):
        return [Finding(CATEGORY, f"{name} is permissive", LOW,
                        f"Policy '{policy}' still sends full URLs to other sites.",
                        "Prefer strict-origin-when-cross-origin or no-referrer.")]
    return [Finding(CATEGORY, f"{name} is set", INFO, f"Value: {value}")]
