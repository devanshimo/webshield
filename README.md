# WebShield

A small, **passive** web-security scanner written in Python. Give it a URL and it makes a normal HTTP request, inspects the response, and prints a report of security findings with severity ratings and short fixes.

> Built as a learning/portfolio project. It is intentionally small so every line can be explained.

---

## 1. What WebShield does

From one URL, WebShield checks:

- **HTTPS**: is the final page served over HTTPS, and does plain HTTP redirect to HTTPS?
- **Security headers**: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`
- **Cookies**: `Secure`, `HttpOnly`, and `SameSite` flags
- **Information disclosure**: `Server`, `X-Powered-By`, and other headers that reveal technology or version numbers

It then prints the target, HTTP status, final URL after redirects, every finding with a severity and remediation, and a summary count by severity.

## 2. Architecture

```
webshield/
├── scanner.py            # CLI entry point + orchestration + report printing
├── checks/
│   ├── __init__.py       # Finding dataclass and severity constants
│   ├── transport.py      # HTTPS and HTTP->HTTPS redirect checks
│   ├── headers.py        # Security-header checks
│   ├── cookies.py        # Cookie-flag checks
│   └── information.py    # Information-disclosure checks
├── reports/              # Saved reports go here (--save)
├── requirements.txt
├── README.md
└── .gitignore
```

**Flow:** `scanner.py` validates the URL → makes one GET request (following redirects) → passes the response to each check module → sorts findings by severity → prints the report.

Every check function returns a list of `Finding` objects (category, title, severity, detail, remediation). Because all checks share this one shape, the report code does not need to know anything about individual checks.

`checks/transport.py` is one file beyond the minimum layout; it keeps the HTTPS logic out of `scanner.py`.

## 3. Install

Requires Python 3.8+.

```bash
git clone <your-repo-url> webshield
cd webshield
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 4. Run

```bash
python scanner.py https://example.com
python scanner.py https://example.com --timeout 5    # per-request timeout in seconds (default 10)
python scanner.py https://example.com --save         # also writes a .txt report into reports/
```

If you omit the scheme (`example.com`), `https://` is assumed.

**Exit codes:** `0` scan finished with no HIGH findings, `1` scan finished with at least one HIGH finding, `2` scan could not run (invalid URL, connection failure, timeout, SSL error, ...).

**Error handling:** invalid URLs, unsupported schemes, DNS/connection failures, timeouts, SSL certificate errors, redirect loops, and HTTP error responses (4xx/5xx, which are still analysed and noted in the report) are all handled with readable messages instead of stack traces.

## 5. What each check means

### HTTPS
| Check | Why it matters |
|---|---|
| Final page uses HTTPS | Without TLS, traffic (including cookies and passwords) can be read or altered on the network. |
| HTTP redirects to HTTPS | Users often type a bare domain, which loads over HTTP first. A redirect upgrades them to the secure site. |

### Security headers
| Header | What it does |
|---|---|
| `Strict-Transport-Security` (HSTS) | Tells browsers to use HTTPS only for this site for a set time, defeating SSL-stripping downgrade attacks. |
| `Content-Security-Policy` (CSP) | Restricts where scripts, styles, and other content may load from; a key defence-in-depth control against XSS. |
| `X-Frame-Options` | Controls whether the page may be embedded in a frame, preventing clickjacking. CSP `frame-ancestors` is the modern equivalent and is accepted too. |
| `X-Content-Type-Options` | `nosniff` stops browsers from guessing content types, which can turn uploads into executable scripts. |
| `Referrer-Policy` | Controls how much of the current URL is sent to other sites, limiting leakage of tokens or IDs in URLs. |

### Cookies
| Flag | What it does |
|---|---|
| `Secure` | Cookie is only sent over HTTPS. |
| `HttpOnly` | JavaScript cannot read the cookie, limiting damage from XSS. |
| `SameSite` | Limits sending the cookie on cross-site requests, reducing CSRF risk. |

Cookies are parsed from the raw `Set-Cookie` headers, including those from redirect hops, because `requests`' cookie jar does not preserve `HttpOnly` or `SameSite`.

### Information disclosure
Headers such as `Server: nginx/1.18.0` or `X-Powered-By: PHP/7.4` tell an attacker exactly which software to research. WebShield checks `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, and `X-Generator`.

## 6. Severity methodology

Severities are simple rules of thumb, not a CVSS score.

| Severity | Meaning | Examples in WebShield |
|---|---|---|
| **HIGH** | Directly exposes users or sessions | Page served over plain HTTP; session-like cookie without `Secure` |
| **MEDIUM** | Missing protection that enables a realistic attack | No HTTP-to-HTTPS redirect; missing HSTS, CSP, or `X-Frame-Options`; cookie without `Secure`; session-like cookie without `HttpOnly`; `SameSite=None` without `Secure` |
| **LOW** | Hardening gap or weak configuration | Missing `X-Content-Type-Options` or `Referrer-Policy`; CSP with `unsafe-inline`; short HSTS max-age; cookie without `HttpOnly` or `SameSite`; version number in `Server`/`X-Powered-By` |
| **INFO** | Informational: a check passed, was skipped, or reveals only a product name | Header present and correct; `X-Powered-By: Express` |

A cookie is treated as "session-like" if its name contains `sess`, `sid`, `token`, `auth`, or `jwt`. This is a name-based heuristic, so it can be wrong in both directions. Session-like cookies get their severity raised one level because losing them means account takeover.

## 7. Example output

This is real output from scanning a deliberately weak local test server (not a public site), trimmed for length:

```
==============================================================================
 WebShield Security Report
==============================================================================
Target URL  : http://127.0.0.1:8766/
HTTP status : 200 OK
Final URL   : http://127.0.0.1:8766/
Redirects   : 0

Findings
------------------------------------------------------------------------------
[HIGH]   Final page is served over plain HTTP
         [HTTPS] Without TLS, anyone on the network path can read or modify
         traffic, including cookies and form data.
         Fix: Obtain a TLS certificate (e.g. Let's Encrypt) and serve the
              whole site over HTTPS.

[HIGH]   Cookie 'sessionid' is missing the Secure flag
         [Cookies] The browser may send this cookie over plain HTTP, where it
         can be intercepted. It looks like a session/auth cookie, so the
         impact is higher.
         Fix: Add the Secure attribute to the Set-Cookie header.

[MEDIUM] Missing X-Frame-Options
         [Headers] The page can be embedded in another site's frame, enabling
         clickjacking (tricking users into clicking hidden UI).
         Fix: Add: X-Frame-Options: DENY (or use CSP frame-ancestors 'none').

[LOW]    Server reveals a version: BaseHTTP/0.6 Python/3.12.3, nginx/1.18.0
         [Information] Exact versions let an attacker look up known
         vulnerabilities for that release.
         Fix: Hide the version (nginx: 'server_tokens off;', Apache:
              'ServerTokens Prod').

[INFO]   X-Content-Type-Options is set
         [Headers] Value: nosniff

... (remaining findings omitted) ...

Summary
------------------------------------------------------------------------------
  HIGH   : 2
  MEDIUM : 2
  LOW    : 4
  INFO   : 5
  TOTAL  : 13
==============================================================================
```

## 8. Limitations

- **Passive and shallow:** it inspects one response (plus one HTTP probe). It does not crawl, so headers or cookies that differ on other pages are not seen.
- **Single-page view:** a login-protected app may return only a login page or error page, and findings describe that response.
- **Presence is not correctness:** a CSP check only flags `unsafe-inline`/`unsafe-eval`; it does not judge whether a policy is actually effective.
- **Heuristics:** the session-cookie detection is name-based; version detection is a simple regex.
- **No TLS inspection:** it does not test protocol versions, cipher suites, or certificate details beyond what `requests` verifies (a failed verification is reported as an SSL error).
- **No vulnerability detection:** it finds missing defences and information leaks, not actual bugs such as XSS or SQL injection.
- **No authentication support.** Scans run as an anonymous visitor.
- It does not read `Set-Cookie` values or evaluate their contents, only their flags.

## 9. Ethical and legal note

Only scan systems you **own** or have **explicit written permission** to test. Although WebShield is passive (a couple of ordinary GET requests, no exploit payloads, no brute forcing), unauthorised scanning can still violate laws and terms of service. You are responsible for how you use this tool.

---

## Interview Notes

**Why `requests`?** It is the standard, readable Python HTTP library: it handles redirects, timeouts, TLS verification, and exceptions with very little code, and exposes `response.history` and `response.url` for redirect analysis. A single well-known dependency kept the project easy to explain. (One caveat: its cookie jar drops `HttpOnly`/`SameSite`, so I parse raw `Set-Cookie` headers instead.)

**Why is it modular?** Each check area lives in its own file and returns the same `Finding` structure. That makes each check testable in isolation, lets me add a new check without touching the report code, and keeps `scanner.py` as simple orchestration. It is also easy to explain: one file, one concern.

**What do security headers do?** They are instructions the server sends so the *browser* enforces extra protections: HSTS forces HTTPS, CSP restricts content sources (mitigating XSS), `X-Frame-Options` blocks framing (clickjacking), `nosniff` blocks MIME sniffing, and `Referrer-Policy` limits URL leakage. They are defence in depth: they reduce the impact of bugs rather than fixing them.

**Why do `Secure`, `HttpOnly`, and `SameSite` matter?** `Secure` keeps cookies off plain HTTP; `HttpOnly` stops JavaScript (and therefore XSS payloads) from reading them; `SameSite` restricts cross-site sending, which mitigates CSRF. Session cookies are effectively credentials, so these flags protect against session theft.

**Limitations of passive scanning:** it can only see what the server volunteers in a response. It cannot find logic flaws, injection bugs, broken access control, or anything behind authentication, and it can produce findings that are context-dependent (for example, a header that is not needed on an API-only endpoint). It is a first-pass hygiene check, not a penetration test.

**Possible future improvements (not implemented):**
- SAST integration, for example running Semgrep on the target's source code
- Nuclei integration for template-based vulnerability checks (with permission)
- Authentication-aware scanning so logged-in pages can be assessed
- CI/CD integration, running the scanner on deploys and failing builds on HIGH findings. The exit code (`1` on HIGH findings) is a small first step in that direction, but no CI integration exists today.
- Crawling multiple pages, JSON/HTML report output, and automated tests for each check module
