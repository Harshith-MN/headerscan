# HTTP Security Header & Cookie Report

- **Source:** vulnerable.txt
- **URL:** https://shop.example.test/account
- **Status:** 200
- **Content-Type:** text/html

## Summary

| Severity | Count |
|---|---|
| High | 0 |
| Medium | 8 |
| Low | 10 |
| Info | 4 |

## Findings (highest priority first)

### [MEDIUM] Session-like cookie 'PHPSESSID' lacks HttpOnly

- **Rule:** `COOKIE-NO-HTTPONLY`
- **Evidence:** `Set-Cookie: PHPSESSID=<redacted>; path=/`
- **Why it matters:** Any XSS can read the cookie and hijack the session.
- **Fix:** Add HttpOnly.

### [MEDIUM] Cookie 'PHPSESSID' lacks Secure flag

- **Rule:** `COOKIE-NO-SECURE`
- **Evidence:** `Set-Cookie: PHPSESSID=<redacted>; path=/`
- **Why it matters:** The cookie can be sent over plain HTTP and sniffed or injected.
- **Fix:** Add the Secure attribute.

### [MEDIUM] Cookie 'tracking' uses SameSite=None without Secure

- **Rule:** `COOKIE-SAMESITE-NONE-INSECURE`
- **Evidence:** `Set-Cookie: tracking=<redacted>; samesite=None`
- **Why it matters:** Browsers reject SameSite=None cookies that are not Secure.
- **Fix:** Add Secure or change SameSite.

### [MEDIUM] CORS wildcard origin combined with credentials

- **Rule:** `CORS-WILDCARD-CREDS`
- **Evidence:** `Access-Control-Allow-Origin: *; Allow-Credentials: true`
- **Why it matters:** Browsers reject this pair, but it signals a misconfigured policy that may be 'fixed' by reflecting any Origin.
- **Fix:** Use an explicit origin allow-list; never reflect arbitrary Origin with credentials.

### [MEDIUM] CSP script-src allows 'unsafe-eval'

- **Rule:** `CSP-UNSAFE-EVAL`
- **Evidence:** `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:`
- **Why it matters:** eval()-style execution is permitted, enabling several XSS gadgets.
- **Fix:** Remove 'unsafe-eval' and refactor code that needs eval/new Function.

### [MEDIUM] CSP script-src allows 'unsafe-inline'

- **Rule:** `CSP-UNSAFE-INLINE`
- **Evidence:** `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:`
- **Why it matters:** Inline scripts run, which defeats most of CSP's XSS protection.
- **Fix:** Use nonces or hashes instead of 'unsafe-inline'.

### [MEDIUM] CSP script-src uses overly broad source (https:)

- **Rule:** `CSP-WILDCARD-SCRIPT`
- **Evidence:** `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:`
- **Why it matters:** Scripts can be loaded from any matching origin, including attacker-controlled ones.
- **Fix:** List specific trusted hosts or use nonces with 'strict-dynamic'.

### [MEDIUM] No clickjacking protection (X-Frame-Options / frame-ancestors)

- **Rule:** `XFO-MISSING`
- **Evidence:** `(neither header present)`
- **Why it matters:** The page can be framed by any site and used for clickjacking.
- **Fix:** Add Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).

### [LOW] Session-like cookie 'PHPSESSID' lacks SameSite

- **Rule:** `COOKIE-NO-SAMESITE`
- **Evidence:** `Set-Cookie: PHPSESSID=<redacted>; path=/`
- **Why it matters:** Relies on browser defaults (Lax) for CSRF protection; older browsers differ.
- **Fix:** Set SameSite=Lax or Strict explicitly.

### [LOW] Session-like cookie '__Host-auth' lacks SameSite

- **Rule:** `COOKIE-NO-SAMESITE`
- **Evidence:** `Set-Cookie: __Host-auth=<redacted>; secure; domain=shop.example.test; path=/; httponly`
- **Why it matters:** Relies on browser defaults (Lax) for CSRF protection; older browsers differ.
- **Fix:** Set SameSite=Lax or Strict explicitly.

### [LOW] Cookie 'theme' lacks Secure flag

- **Rule:** `COOKIE-NO-SECURE`
- **Evidence:** `Set-Cookie: theme=<redacted>; path=/`
- **Why it matters:** The cookie can be sent over plain HTTP and sniffed or injected.
- **Fix:** Add the Secure attribute.

### [LOW] Cookie 'tracking' lacks Secure flag

- **Rule:** `COOKIE-NO-SECURE`
- **Evidence:** `Set-Cookie: tracking=<redacted>; samesite=None`
- **Why it matters:** The cookie can be sent over plain HTTP and sniffed or injected.
- **Fix:** Add the Secure attribute.

### [LOW] Cookie '__Host-auth' violates __Host- prefix rules

- **Rule:** `COOKIE-PREFIX`
- **Evidence:** `Set-Cookie: __Host-auth=<redacted>; secure; domain=shop.example.test; path=/; httponly`
- **Why it matters:** __Host- requires Secure, Path=/ and no Domain; browsers drop the cookie otherwise.
- **Fix:** Fix the attributes or drop the prefix.

### [LOW] CSP lacks base-uri

- **Rule:** `CSP-NO-BASE-URI`
- **Evidence:** `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:`
- **Why it matters:** Injected <base> tags could redirect relative URLs.
- **Fix:** Add base-uri 'none' or 'self'.

### [LOW] x-powered-by header reveals technology

- **Rule:** `DISCLOSE-POWEREDBY`
- **Evidence:** `x-powered-by: PHP/7.2.1`
- **Why it matters:** Reveals the stack/version to attackers.
- **Fix:** Remove the header.

### [LOW] Server header discloses a version

- **Rule:** `DISCLOSE-SERVER`
- **Evidence:** `Server: Apache/2.4.29 (Ubuntu)`
- **Why it matters:** Exact versions help attackers match known CVEs.
- **Fix:** Remove the version (e.g. ServerTokens Prod / server_tokens off).

### [LOW] HSTS max-age is short (300 s)

- **Rule:** `HSTS-SHORT`
- **Evidence:** `Strict-Transport-Security: max-age=300`
- **Why it matters:** A short window leaves users unprotected once it expires.
- **Fix:** Raise max-age to >= 31536000 (1 year).

### [LOW] X-Content-Type-Options header missing

- **Rule:** `XCTO-MISSING`
- **Evidence:** `(header absent)`
- **Why it matters:** Browsers may MIME-sniff responses, which can turn uploads/JSON into executable content.
- **Fix:** Add: X-Content-Type-Options: nosniff

### [INFO] Cookie 'theme' lacks HttpOnly

- **Rule:** `COOKIE-NO-HTTPONLY`
- **Evidence:** `Set-Cookie: theme=<redacted>; path=/`
- **Why it matters:** Name does not look like a session cookie; JS access may be intended. Verify.
- **Fix:** Add HttpOnly if client scripts do not need it.

### [INFO] Cookie 'tracking' lacks HttpOnly

- **Rule:** `COOKIE-NO-HTTPONLY`
- **Evidence:** `Set-Cookie: tracking=<redacted>; samesite=None`
- **Why it matters:** Name does not look like a session cookie; JS access may be intended. Verify.
- **Fix:** Add HttpOnly if client scripts do not need it.

### [INFO] Permissions-Policy header missing

- **Rule:** `PERMISSIONS-MISSING`
- **Evidence:** `(header absent)`
- **Why it matters:** Powerful browser features are not explicitly restricted.
- **Fix:** Add e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()

### [INFO] Referrer-Policy header missing

- **Rule:** `REFERRER-MISSING`
- **Evidence:** `(header absent)`
- **Why it matters:** Modern browsers default to strict-origin-when-cross-origin, so impact is small.
- **Fix:** Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).

## Checks intentionally NOT flagged (false-positive handling)

- `COOKIE-NO-HTTPONLY:XSRF-TOKEN`: CSRF/XSRF token cookies are intentionally readable by JavaScript (double-submit pattern).

## Checks passed

_None._
