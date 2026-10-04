"""Cookie security checks (Secure, HttpOnly, SameSite).

We parse the raw Set-Cookie headers instead of using `response.cookies`,
because requests' cookie jar does not keep the HttpOnly or SameSite flags.
"""

import re

from . import Finding, HIGH, MEDIUM, LOW, INFO

CATEGORY = "Cookies"

# Cookie names that look like they hold a session or credential (a simple heuristic).
SESSION_NAME = re.compile(r"sess|sid|token|auth|jwt", re.IGNORECASE)


def check_cookies(response):
    """Inspect every cookie set by the final response and any redirect hops."""
    set_cookie_headers = _raw_set_cookie_headers(response)
    if not set_cookie_headers:
        return [Finding(CATEGORY, "No cookies set", INFO,
                        "The response did not set any cookies, so no cookie flags to check.")]

    findings = []
    for header in set_cookie_headers:
        name, attrs = _parse_set_cookie(header)
        findings += _check_one_cookie(name, attrs)
    return findings


def _raw_set_cookie_headers(response):
    """Collect Set-Cookie header lines from the redirect chain plus the final response."""
    headers = []
    for resp in list(response.history) + [response]:
        raw_headers = getattr(resp.raw, "headers", None)
        if raw_headers is not None:
            headers.extend(raw_headers.getlist("Set-Cookie"))
    return headers


def _parse_set_cookie(header):
    """Split 'name=value; Secure; SameSite=Lax' into ('name', {'secure': '', 'samesite': 'Lax'})."""
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for part in parts[1:]:
        if part:
            key, _, value = part.partition("=")
            attrs[key.strip().lower()] = value.strip()
    return name, attrs


def _bump(severity):
    """Raise severity one level (used for session-like cookies, where impact is higher)."""
    return {LOW: MEDIUM, MEDIUM: HIGH}.get(severity, severity)


def _check_one_cookie(name, attrs):
    is_session = bool(SESSION_NAME.search(name))
    note = " It looks like a session/auth cookie, so the impact is higher." if is_session else ""
    findings = []

    if "secure" not in attrs:
        sev = _bump(MEDIUM) if is_session else MEDIUM
        findings.append(Finding(
            CATEGORY, f"Cookie '{name}' is missing the Secure flag", sev,
            "The browser may send this cookie over plain HTTP, where it can be intercepted." + note,
            "Add the Secure attribute to the Set-Cookie header."))

    if "httponly" not in attrs:
        sev = _bump(LOW) if is_session else LOW
        findings.append(Finding(
            CATEGORY, f"Cookie '{name}' is missing the HttpOnly flag", sev,
            "JavaScript can read this cookie, so an XSS bug could steal it." + note,
            "Add the HttpOnly attribute to the Set-Cookie header."))

    samesite = attrs.get("samesite")
    if samesite is None:
        findings.append(Finding(
            CATEGORY, f"Cookie '{name}' is missing the SameSite attribute", LOW,
            "Without SameSite the cookie's cross-site behaviour depends on browser defaults, "
            "which weakens CSRF protection.",
            "Add SameSite=Lax (or Strict) unless cross-site use is genuinely required."))
    elif samesite.lower() == "none" and "secure" not in attrs:
        findings.append(Finding(
            CATEGORY, f"Cookie '{name}' uses SameSite=None without Secure", MEDIUM,
            "SameSite=None sends the cookie on all cross-site requests and must be paired "
            "with Secure; browsers reject it otherwise.",
            "Add Secure, or switch to SameSite=Lax."))

    if not findings:
        findings.append(Finding(CATEGORY, f"Cookie '{name}' has Secure, HttpOnly and SameSite", INFO,
                                f"SameSite={samesite}"))
    return findings
