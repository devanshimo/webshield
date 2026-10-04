"""HTTPS checks: is the site served over HTTPS, and does HTTP redirect to it?"""

from urllib.parse import urlsplit, urlunsplit

import requests

from . import Finding, HIGH, MEDIUM, INFO

CATEGORY = "HTTPS"


def check_https(final_url):
    """Check the scheme of the final URL (after all redirects)."""
    if urlsplit(final_url).scheme == "https":
        return [Finding(CATEGORY, "Final page is served over HTTPS", INFO,
                        "Traffic to the final URL is encrypted in transit.")]
    return [Finding(
        CATEGORY, "Final page is served over plain HTTP", HIGH,
        "Without TLS, anyone on the network path can read or modify traffic, "
        "including cookies and form data.",
        "Obtain a TLS certificate (e.g. Let's Encrypt) and serve the whole site over HTTPS.")]


def check_http_redirect(target_url, timeout, request_headers):
    """Request the http:// version of the site and see whether it ends up on https://.

    This is a normal GET request (the same thing a browser does when someone
    types the address without 'https'). We skip URLs with a custom port because
    swapping the scheme on a custom port would test a different service.
    """
    parts = urlsplit(target_url)
    if parts.port is not None:
        return [Finding(CATEGORY, "HTTP-to-HTTPS redirect not tested", INFO,
                        "The URL has a custom port, so the plain-HTTP variant was not probed.")]

    http_url = urlunsplit(("http", parts.netloc, parts.path or "/", parts.query, ""))
    try:
        response = requests.get(http_url, headers=request_headers,
                                timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        return [Finding(CATEGORY, "HTTP-to-HTTPS redirect could not be tested", INFO,
                        f"The plain-HTTP request failed ({type(exc).__name__}). "
                        "This is common when port 80 is closed.")]

    if urlsplit(response.url).scheme == "https":
        return [Finding(CATEGORY, "HTTP redirects to HTTPS", INFO,
                        "Visitors who type the plain-HTTP address are sent to the secure site.")]
    return [Finding(
        CATEGORY, "HTTP does not redirect to HTTPS", MEDIUM,
        "The site answers on plain HTTP without upgrading the visitor, "
        "leaving a window for downgrade and interception attacks.",
        "Configure the web server to return a 301 redirect from http:// to https://.")]
