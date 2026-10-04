"""Information-disclosure checks: do response headers reveal the technology stack?"""

import re

from . import Finding, LOW, INFO

CATEGORY = "Information"

# Headers that commonly reveal software details.
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]

# Matches things like "1.18.0" or "/2" (as in "nginx/1.18.0" or "Apache/2").
VERSION_PATTERN = re.compile(r"\d+\.\d+|/\d+")

REMEDIATION = {
    "Server": "Hide or minimise server details in the server configuration.",
    "X-Powered-By": "Remove the header in the application/framework configuration.",
}
DEFAULT_REMEDIATION = "Remove or genericise this header in the server/framework configuration."


def check_information_disclosure(headers):
    """Flag headers that reveal technology names or, worse, version numbers."""
    findings = []
    for name in DISCLOSURE_HEADERS:
        value = headers.get(name)
        if value is None:
            continue

        if VERSION_PATTERN.search(value):
            findings.append(Finding(
                CATEGORY, f"{name} reveals a version: {value}", LOW,
                "Exact versions let an attacker look up known vulnerabilities for that release.",
                REMEDIATION.get(name, DEFAULT_REMEDIATION)))
        else:
            findings.append(Finding(
                CATEGORY, f"{name} reveals technology: {value}", INFO,
                "The technology name alone is low risk but helps attackers profile the target.",
                REMEDIATION.get(name, DEFAULT_REMEDIATION)))

    if not findings:
        findings.append(Finding(CATEGORY, "No technology-revealing headers found", INFO,
                                f"Checked: {', '.join(DISCLOSURE_HEADERS)}."))
    return findings
