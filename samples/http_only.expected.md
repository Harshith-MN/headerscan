# HTTP Security Header & Cookie Report

- **Source:** http_only.txt
- **URL:** http://legacy.example.test/login
- **Status:** 200
- **Content-Type:** text/html

## Summary

| Severity | Count |
|---|---|
| High | 0 |
| Medium | 2 |
| Low | 2 |
| Info | 2 |

## Findings (highest priority first)

### [MEDIUM] Content-Security-Policy header missing

- **Rule:** `CSP-MISSING`
- **Evidence:** `(header absent)`
- **Why it matters:** No CSP means XSS has no second line of defence.
- **Fix:** Start with: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'

### [MEDIUM] No clickjacking protection (X-Frame-Options / frame-ancestors)

- **Rule:** `XFO-MISSING`
- **Evidence:** `(neither header present)`
- **Why it matters:** The page can be framed by any site and used for clickjacking.
- **Fix:** Add Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).

### [LOW] Session-like cookie 'sessionid' lacks SameSite

- **Rule:** `COOKIE-NO-SAMESITE`
- **Evidence:** `Set-Cookie: sessionid=<redacted>; path=/; httponly`
- **Why it matters:** Relies on browser defaults (Lax) for CSRF protection; older browsers differ.
- **Fix:** Set SameSite=Lax or Strict explicitly.

### [LOW] X-Content-Type-Options header missing

- **Rule:** `XCTO-MISSING`
- **Evidence:** `(header absent)`
- **Why it matters:** Browsers may MIME-sniff responses, which can turn uploads/JSON into executable content.
- **Fix:** Add: X-Content-Type-Options: nosniff

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

- `HSTS-MISSING`: Response was served over plain HTTP; browsers ignore HSTS on HTTP (RFC 6797). The real issue is the lack of HTTPS.
- `COOKIE-NO-SECURE:sessionid`: Response is plain HTTP; browsers refuse Secure cookies there. Fix is HTTPS, not the flag.

## Checks passed

_None._
