# HTTP Security Header & Cookie Report

- **Source:** json_api.txt
- **URL:** https://api.example.test/v1/status
- **Status:** 200
- **Content-Type:** application/json

## Summary

| Severity | Count |
|---|---|
| High | 0 |
| Medium | 0 |
| Low | 1 |
| Info | 0 |

## Findings (highest priority first)

### [LOW] X-Content-Type-Options header missing

- **Rule:** `XCTO-MISSING`
- **Evidence:** `(header absent)`
- **Why it matters:** Browsers may MIME-sniff responses, which can turn uploads/JSON into executable content.
- **Fix:** Add: X-Content-Type-Options: nosniff

## Checks intentionally NOT flagged (false-positive handling)

- `CSP-MISSING`: Content-Type is application/json, not an HTML document. CSP mainly protects rendered documents.
- `XFO-MISSING`: Content-Type is application/json, not an HTML document. Clickjacking applies to framed documents.
- `DISCLOSE-SERVER`: Server header ('cloudflare') names software but gives no version; not actionable.
- `CORS-WILDCARD`: ACAO: * without credentials is normal for public, unauthenticated APIs.

## Checks passed

- HSTS: max-age=31536000
