# HTTP Security Header & Cookie Report

- **Source:** hardened.txt
- **URL:** https://secure.example.test/
- **Status:** 200
- **Content-Type:** text/html

## Summary

| Severity | Count |
|---|---|
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |

## Findings (highest priority first)

_No findings._

## Checks intentionally NOT flagged (false-positive handling)

- `CSP-UNSAFE-INLINE`: 'unsafe-inline' is present but ignored by modern browsers because a nonce/hash/'strict-dynamic' is also present (backward-compat pattern).
- `XFO-MISSING`: CSP frame-ancestors is set and supersedes X-Frame-Options in modern browsers.
- `DISCLOSE-SERVER`: Server header ('nginx') names software but gives no version; not actionable.

## Checks passed

- HSTS: max-age=63072000
- XCTO: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
