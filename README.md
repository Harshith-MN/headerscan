# headerscan

Offline analyser for HTTP security headers and cookies that produces a prioritised report **and explains what it chose not to flag**.

## Security problem being solved
Header/cookie scanners are noisy. They flag "missing CSP" on JSON APIs, "missing HSTS" on HTTP pages, or `unsafe-inline` next to a nonce, and testers waste time triaging false positives. headerscan checks context (scheme, content type, status code, CSP interplay, cookie role) before reporting, and lists every suppressed check with the reason.

## Intended users
Pentesters, bug-bounty hunters and AppSec engineers triaging saved responses from `curl -i`, Burp or ZAP, and CI pipelines gating on header regressions.

## Main features
- Checks: HSTS, CSP (missing, report-only, unsafe-inline/eval, broad sources, object-src, base-uri), clickjacking (X-Frame-Options / frame-ancestors), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, version disclosure (Server, X-Powered-By, ASP.NET), CORS (wildcard+credentials, null origin, missing Vary), cookies (Secure, HttpOnly, SameSite, `__Host-`/`__Secure-` prefixes).
- Severity-ranked Markdown or JSON output; each finding has evidence, impact and fix.
- "Not flagged" section documenting false-positive suppression.
- Cookie **values are never printed** (redacted).
- `--fail-on` exit code for CI.

## Technology
Python 3.8+, standard library only. No network access, no API key.

## Installation
```bash
git clone <your-repo-url> && cd headerscan
python3 --version   # 3.8 or newer
```

## Usage
```bash
# 1. Save a response you are AUTHORISED to test (optional first line gives the URL)
echo "# URL: https://target.example/" > resp.txt
curl -sI https://target.example/ >> resp.txt

# 2. Analyse
python3 headerscan.py resp.txt                    # Markdown to stdout
python3 headerscan.py resp.txt --format json -o report.json
python3 headerscan.py resp.txt --fail-on medium   # exit 1 if medium+ finding
```
Exit codes: `0` ok, `1` findings at/above `--fail-on`, `2` unreadable/invalid input.

## Sample command, input and output
```bash
python3 headerscan.py samples/vulnerable.txt
```
| Sample | Shows | Expected output |
|---|---|---|
| `samples/vulnerable.txt` | Many real issues (8 medium, 10 low, 4 info) | `vulnerable.expected.md/.json` |
| `samples/hardened.txt` | Clean result; nonce + `unsafe-inline` and `frame-ancestors` handled | `hardened.expected.md/.json` |
| `samples/json_api.txt` | JSON API: CSP/XFO and `ACAO: *` not flagged | `json_api.expected.md/.json` |
| `samples/http_only.txt` | HTTP page: HSTS and Secure-flag demands suppressed | `http_only.expected.md/.json` |

Excerpt of `vulnerable.expected.md`:
```
### [MEDIUM] Session-like cookie 'PHPSESSID' lacks HttpOnly
- Evidence: Set-Cookie: PHPSESSID=<redacted>; path=/
- Why it matters: Any XSS can read the cookie and hijack the session.
- Fix: Add HttpOnly.
```

## Tests
```bash
python3 -m unittest discover -v tests
```
12 tests: successful detection, 6 false-positive cases, redirect handling, cookie-value redaction, and byte-for-byte comparison against the expected sample outputs.

## False positives handled (and why)
| Situation | Behaviour |
|---|---|
| `'unsafe-inline'` with nonce/hash/`'strict-dynamic'` | Not flagged: browsers ignore it |
| `X-Frame-Options` absent but CSP `frame-ancestors` set | Not flagged: frame-ancestors supersedes |
| JSON/non-HTML or redirect response | CSP/XFO/Permissions checks skipped |
| HSTS / Secure flag on `http://` response | Suppressed: browsers ignore HSTS on HTTP; real fix is HTTPS |
| `XSRF-TOKEN`/`csrf` cookie without HttpOnly | Not flagged: JS must read it (double-submit) |
| `Server: nginx` (no version) | Not flagged: nothing actionable |
| `ACAO: *` without credentials | Not flagged: normal for public APIs |

## Security considerations
- Analyses saved files only; sends no traffic, so it cannot be used to attack a system.
- Only test targets you own or are authorised to test.
- Cookie values are redacted; do not commit real session cookies to the repo (sample values are dummies).

## Known limitations
- Header analysis only: cannot see the HTML body, so inline `<meta>` CSP, JS-set cookies and real XSS exposure are invisible.
- Cookie "sensitivity" is guessed from the name (regex); a session cookie called `x1` is treated as non-sensitive.
- Multiple CSP headers are analysed independently rather than intersected.
- Multi-response files (curl redirects) analyse the last response; a body that starts a line with `HTTP/1.1 200` would confuse it.
- Does not judge CSP host allow-lists for known JSONP/bypass domains.
- One response per run.

## Future improvements
- Optional authorised live fetch with an explicit consent flag.
- Parse HAR / Burp / ZAP exports and batch many responses.
- CSP bypass-domain database; CSP intersection of multiple policies.
- SARIF output for GitHub code scanning.
