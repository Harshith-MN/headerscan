#!/usr/bin/env python3
"""headerscan - offline analyser for HTTP security headers and cookies.

Input : a saved raw HTTP response (e.g. `curl -sI https://target`), optionally
        preceded by a line `# URL: https://target/path`.
Output: a prioritised Markdown or JSON report, including a list of checks that
        were deliberately NOT flagged (false-positive handling).

No network access is performed. Standard library only (Python 3.8+).
"""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

SEVERITIES = ["high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})")
NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
HSTS_MIN_SECONDS = 15552000  # 180 days
HTML_TYPES = {"text/html", "application/xhtml+xml"}


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
class Response:
    def __init__(self):
        self.url = None
        self.status = None
        self.headers = {}   # lowercase name -> list of raw values
        self.warnings = []

    def all(self, name):
        return self.headers.get(name.lower(), [])

    def get(self, name):
        vals = self.all(name)
        return ", ".join(vals) if vals else None


def parse_response(text):
    """Parse a raw HTTP response. If several responses are present
    (curl -i following redirects) the LAST one is analysed."""
    resp = Response()
    state = "pre"  # pre -> headers -> body
    last = None
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        m = STATUS_RE.match(line)
        if state == "pre":
            if line.lower().startswith("# url:"):
                resp.url = line.split(":", 1)[1].strip()
            elif m:
                resp.status, state = int(m.group(1)), "headers"
            elif line.strip() and not line.startswith("#") and ":" in line:
                state = "headers"
                last = _add_header(resp, line)
        elif state == "headers":
            if not line.strip():
                state = "body"
            elif m:  # new response block without blank line
                url, warns = resp.url, resp.warnings
                resp = Response()
                resp.url, resp.warnings = url, warns
                resp.status = int(m.group(1))
            elif line[0] in " \t" and last:  # obsolete line folding
                resp.headers[last][-1] += " " + line.strip()
            else:
                last = _add_header(resp, line)
        elif state == "body" and m:  # next response after redirect
            url, warns = resp.url, resp.warnings
            resp = Response()
            resp.url, resp.warnings = url, warns
            resp.status, state = int(m.group(1)), "headers"
    return resp


def _add_header(resp, line):
    name, sep, value = line.partition(":")
    name = name.strip()
    if not sep or not NAME_RE.match(name):
        resp.warnings.append("Ignored malformed header line: %r" % line[:60])
        return None
    key = name.lower()
    resp.headers.setdefault(key, []).append(value.strip())
    return key


def parse_csp(value):
    """Directive name -> list of tokens. First occurrence of a directive wins."""
    directives = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if toks and toks[0].lower() not in directives:
            directives[toks[0].lower()] = toks[1:]
    return directives


def parse_cookie(raw):
    parts = [p.strip() for p in raw.split(";")]
    name, sep, _value = parts[0].partition("=")
    if not sep or not name.strip():
        return None
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        if k.strip():
            attrs[k.strip().lower()] = v.strip()
    return name.strip(), attrs


# --------------------------------------------------------------------------
# Report container
# --------------------------------------------------------------------------
class Report:
    def __init__(self, resp, source):
        self.resp, self.source = resp, source
        self.findings, self.skipped, self.passed, self.notes = [], [], [], []
        self.scheme = urlsplit(resp.url).scheme.lower() if resp.url else ""
        if not self.scheme:
            self.notes.append("No '# URL:' line found; assuming the response was served over HTTPS.")
        ct = (resp.get("content-type") or "").split(";")[0].strip().lower()
        self.content_type = ct
        redirect = resp.status is not None and 300 <= resp.status < 400
        if redirect:
            self.doc_ok, self.doc_reason = False, "Redirect response (%s) renders no document." % resp.status
        elif ct and ct not in HTML_TYPES:
            self.doc_ok, self.doc_reason = False, "Content-Type is %s, not an HTML document." % ct
        else:
            self.doc_ok, self.doc_reason = True, ""
        for w in resp.warnings:
            self.notes.append(w)

    def add(self, rule, sev, title, evidence, why, fix):
        self.findings.append(dict(rule=rule, severity=sev, title=title,
                                  evidence=evidence, why=why, fix=fix))

    def skip(self, rule, reason):
        self.skipped.append(dict(rule=rule, reason=reason))

    def ok(self, rule, msg):
        self.passed.append("%s: %s" % (rule, msg))

    def sorted_findings(self):
        return sorted(self.findings, key=lambda f: (RANK[f["severity"]], f["rule"]))


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------
def check_hsts(r):
    v = r.resp.get("strict-transport-security")
    if r.scheme == "http":
        r.skip("HSTS-MISSING", "Response was served over plain HTTP; browsers ignore HSTS on HTTP "
               "(RFC 6797). The real issue is the lack of HTTPS.")
        return
    if v is None:
        r.add("HSTS-MISSING", "medium", "Strict-Transport-Security header missing",
              "(header absent)",
              "Without HSTS, users can be downgraded to HTTP by a network attacker (SSL stripping).",
              "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
        return
    m = re.search(r'max-age\s*=\s*"?(\d+)"?', v, re.I)
    if not m:
        r.add("HSTS-NO-MAXAGE", "medium", "HSTS header has no valid max-age",
              "Strict-Transport-Security: " + v, "Browsers ignore HSTS without max-age.",
              "Set max-age to at least 31536000.")
        return
    age = int(m.group(1))
    if age == 0:
        r.add("HSTS-ZERO", "medium", "HSTS max-age is 0 (HSTS is being disabled)",
              "Strict-Transport-Security: " + v, "max-age=0 tells browsers to forget the host.",
              "Use a long max-age (>= 31536000) unless you are deliberately removing HSTS.")
    elif age < HSTS_MIN_SECONDS:
        r.add("HSTS-SHORT", "low", "HSTS max-age is short (%d s)" % age,
              "Strict-Transport-Security: " + v,
              "A short window leaves users unprotected once it expires.",
              "Raise max-age to >= 31536000 (1 year).")
    else:
        r.ok("HSTS", "max-age=%d" % age)
    if "preload" in v.lower() and not (age >= 31536000 and "includesubdomains" in v.lower()):
        r.add("HSTS-PRELOAD-INVALID", "low", "HSTS 'preload' set but preload requirements not met",
              "Strict-Transport-Security: " + v,
              "Preload lists require max-age >= 31536000 and includeSubDomains.",
              "Add includeSubDomains and raise max-age, or remove 'preload'.")


def check_csp(r):
    enforced = r.resp.all("content-security-policy")
    report_only = r.resp.all("content-security-policy-report-only")
    if not enforced:
        if not r.doc_ok:
            r.skip("CSP-MISSING", r.doc_reason + " CSP mainly protects rendered documents.")
        elif report_only:
            r.add("CSP-REPORT-ONLY", "low", "CSP is report-only (not enforced)",
                  "Content-Security-Policy-Report-Only present, no enforcing CSP",
                  "Report-Only policies log violations but block nothing.",
                  "Move to Content-Security-Policy once reports are clean.")
        else:
            r.add("CSP-MISSING", "medium", "Content-Security-Policy header missing",
                  "(header absent)",
                  "No CSP means XSS has no second line of defence.",
                  "Start with: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        return
    for raw in enforced:
        p = parse_csp(raw)
        ev = "Content-Security-Policy: " + raw
        src = p.get("script-src", p.get("default-src"))
        if src is None:
            r.add("CSP-NO-SCRIPT-CONTROL", "medium", "CSP does not restrict scripts", ev,
                  "Neither script-src nor default-src is set, so any script source is allowed.",
                  "Add script-src (preferably nonce-based) or default-src 'self'.")
        else:
            toks = [t.lower() for t in src]
            protected = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                            or t == "'strict-dynamic'" for t in toks)
            if "'unsafe-inline'" in toks:
                if protected:
                    r.skip("CSP-UNSAFE-INLINE", "'unsafe-inline' is present but ignored by modern browsers "
                           "because a nonce/hash/'strict-dynamic' is also present (backward-compat pattern).")
                else:
                    r.add("CSP-UNSAFE-INLINE", "medium", "CSP script-src allows 'unsafe-inline'", ev,
                          "Inline scripts run, which defeats most of CSP's XSS protection.",
                          "Use nonces or hashes instead of 'unsafe-inline'.")
            if "'unsafe-eval'" in toks:
                r.add("CSP-UNSAFE-EVAL", "medium", "CSP script-src allows 'unsafe-eval'", ev,
                      "eval()-style execution is permitted, enabling several XSS gadgets.",
                      "Remove 'unsafe-eval' and refactor code that needs eval/new Function.")
            if "'strict-dynamic'" not in toks:
                broad = [t for t in toks if t in ("*", "https:", "http:", "data:")]
                if broad:
                    r.add("CSP-WILDCARD-SCRIPT", "medium",
                          "CSP script-src uses overly broad source (%s)" % ", ".join(broad), ev,
                          "Scripts can be loaded from any matching origin, including attacker-controlled ones.",
                          "List specific trusted hosts or use nonces with 'strict-dynamic'.")
        if "object-src" not in p and "default-src" not in p:
            r.add("CSP-NO-OBJECT-SRC", "low", "CSP lacks object-src", ev,
                  "Plugins/<object> are not restricted.", "Add object-src 'none'.")
        if "base-uri" not in p:
            r.add("CSP-NO-BASE-URI", "low", "CSP lacks base-uri", ev,
                  "Injected <base> tags could redirect relative URLs.", "Add base-uri 'none' or 'self'.")


def check_clickjacking(r):
    if not r.doc_ok:
        r.skip("XFO-MISSING", r.doc_reason + " Clickjacking applies to framed documents.")
        return
    has_fa = any("frame-ancestors" in parse_csp(v) for v in r.resp.all("content-security-policy"))
    xfo = r.resp.get("x-frame-options")
    if has_fa:
        r.skip("XFO-MISSING", "CSP frame-ancestors is set and supersedes X-Frame-Options in modern browsers.")
    elif xfo is None:
        r.add("XFO-MISSING", "medium", "No clickjacking protection (X-Frame-Options / frame-ancestors)",
              "(neither header present)", "The page can be framed by any site and used for clickjacking.",
              "Add Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).")
    elif xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        r.ok("XFO", xfo)
    else:
        r.add("XFO-INVALID", "low", "X-Frame-Options has an unsupported value",
              "X-Frame-Options: " + xfo, "ALLOW-FROM and unknown values are ignored by modern browsers.",
              "Use DENY/SAMEORIGIN or CSP frame-ancestors.")


def check_nosniff(r):
    v = r.resp.get("x-content-type-options")
    if v is None:
        r.add("XCTO-MISSING", "low", "X-Content-Type-Options header missing", "(header absent)",
              "Browsers may MIME-sniff responses, which can turn uploads/JSON into executable content.",
              "Add: X-Content-Type-Options: nosniff")
    elif v.strip().lower() != "nosniff":
        r.add("XCTO-INVALID", "low", "X-Content-Type-Options has wrong value",
              "X-Content-Type-Options: " + v, "Only 'nosniff' is defined.", "Set it to nosniff.")
    else:
        r.ok("XCTO", "nosniff")


def check_referrer_permissions(r):
    v = r.resp.get("referrer-policy")
    if v is None:
        if r.doc_ok:
            r.add("REFERRER-MISSING", "info", "Referrer-Policy header missing", "(header absent)",
                  "Modern browsers default to strict-origin-when-cross-origin, so impact is small.",
                  "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).")
    else:
        last = v.split(",")[-1].strip().lower()  # last recognised value wins
        if last in ("unsafe-url", "no-referrer-when-downgrade"):
            r.add("REFERRER-UNSAFE", "low", "Referrer-Policy leaks full URL cross-origin",
                  "Referrer-Policy: " + v, "Full URLs (possibly with tokens) are sent to other sites.",
                  "Use strict-origin-when-cross-origin or no-referrer.")
        else:
            r.ok("Referrer-Policy", last)
    if r.resp.get("permissions-policy") is None and r.doc_ok:
        r.add("PERMISSIONS-MISSING", "info", "Permissions-Policy header missing", "(header absent)",
              "Powerful browser features are not explicitly restricted.",
              "Add e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()")


def check_disclosure(r):
    server = r.resp.get("server")
    if server:
        if re.search(r"\d+\.\d+|/\d", server):
            r.add("DISCLOSE-SERVER", "low", "Server header discloses a version",
                  "Server: " + server, "Exact versions help attackers match known CVEs.",
                  "Remove the version (e.g. ServerTokens Prod / server_tokens off).")
        else:
            r.skip("DISCLOSE-SERVER", "Server header ('%s') names software but gives no version; "
                   "not actionable." % server)
    for h in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = r.resp.get(h)
        if v:
            r.add("DISCLOSE-POWEREDBY", "low", "%s header reveals technology" % h,
                  "%s: %s" % (h, v), "Reveals the stack/version to attackers.", "Remove the header.")


def check_cors(r):
    acao = r.resp.get("access-control-allow-origin")
    if acao is None:
        return
    creds = (r.resp.get("access-control-allow-credentials") or "").strip().lower() == "true"
    vary = (r.resp.get("vary") or "").lower()
    ev = "Access-Control-Allow-Origin: %s%s" % (acao, "; Allow-Credentials: true" if creds else "")
    if acao.strip() == "*":
        if creds:
            r.add("CORS-WILDCARD-CREDS", "medium", "CORS wildcard origin combined with credentials", ev,
                  "Browsers reject this pair, but it signals a misconfigured policy that may be "
                  "'fixed' by reflecting any Origin.",
                  "Use an explicit origin allow-list; never reflect arbitrary Origin with credentials.")
        else:
            r.skip("CORS-WILDCARD", "ACAO: * without credentials is normal for public, unauthenticated APIs.")
    elif acao.strip().lower() == "null":
        r.add("CORS-NULL", "medium", "CORS allows the 'null' origin", ev,
              "Sandboxed iframes and file:// pages send Origin: null, so any attacker can match it.",
              "Remove 'null' from the allow-list.")
    elif creds and "origin" not in vary:
        r.add("CORS-NO-VARY", "low", "Dynamic CORS origin without 'Vary: Origin'", ev,
              "Caches may serve one origin's CORS response to another.", "Add Vary: Origin.")


SESSION_RE = re.compile(r"(sess|sid\b|auth|token|jwt|login|sso|remember|ticket)", re.I)
CSRF_RE = re.compile(r"(csrf|xsrf)", re.I)


def check_cookies(r):
    for raw in r.resp.all("set-cookie"):
        parsed = parse_cookie(raw)
        if not parsed:
            r.notes.append("Could not parse a Set-Cookie header (no name=value).")
            continue
        name, attrs = parsed
        evidence = "Set-Cookie: %s=<redacted>%s" % (
            name, "".join("; " + (k if not v else "%s=%s" % (k, v)) for k, v in attrs.items()))
        is_csrf = bool(CSRF_RE.search(name))
        sensitive = bool(SESSION_RE.search(name)) and not is_csrf
        secure = "secure" in attrs
        lname = name.lower()

        if not secure:
            if r.scheme == "http":
                r.skip("COOKIE-NO-SECURE:" + name, "Response is plain HTTP; browsers refuse Secure cookies "
                       "there. Fix is HTTPS, not the flag.")
            else:
                r.add("COOKIE-NO-SECURE", "medium" if sensitive else "low",
                      "Cookie '%s' lacks Secure flag" % name, evidence,
                      "The cookie can be sent over plain HTTP and sniffed or injected.", "Add the Secure attribute.")
        if "httponly" not in attrs:
            if is_csrf:
                r.skip("COOKIE-NO-HTTPONLY:" + name, "CSRF/XSRF token cookies are intentionally readable by "
                       "JavaScript (double-submit pattern).")
            elif sensitive:
                r.add("COOKIE-NO-HTTPONLY", "medium", "Session-like cookie '%s' lacks HttpOnly" % name,
                      evidence, "Any XSS can read the cookie and hijack the session.", "Add HttpOnly.")
            else:
                r.add("COOKIE-NO-HTTPONLY", "info", "Cookie '%s' lacks HttpOnly" % name, evidence,
                      "Name does not look like a session cookie; JS access may be intended. Verify.",
                      "Add HttpOnly if client scripts do not need it.")
        ss = attrs.get("samesite")
        if ss is None:
            if sensitive:
                r.add("COOKIE-NO-SAMESITE", "low", "Session-like cookie '%s' lacks SameSite" % name,
                      evidence, "Relies on browser defaults (Lax) for CSRF protection; older browsers differ.",
                      "Set SameSite=Lax or Strict explicitly.")
        elif ss.lower() not in ("lax", "strict", "none"):
            r.add("COOKIE-SAMESITE-INVALID", "low", "Cookie '%s' has invalid SameSite value" % name,
                  evidence, "Invalid values are treated as default behaviour.", "Use Lax, Strict or None.")
        elif ss.lower() == "none" and not secure:
            r.add("COOKIE-SAMESITE-NONE-INSECURE", "medium",
                  "Cookie '%s' uses SameSite=None without Secure" % name, evidence,
                  "Browsers reject SameSite=None cookies that are not Secure.", "Add Secure or change SameSite.")
        if lname.startswith("__host-"):
            bad = (not secure) or attrs.get("path") != "/" or "domain" in attrs
            if bad:
                r.add("COOKIE-PREFIX", "low", "Cookie '%s' violates __Host- prefix rules" % name, evidence,
                      "__Host- requires Secure, Path=/ and no Domain; browsers drop the cookie otherwise.",
                      "Fix the attributes or drop the prefix.")
        elif lname.startswith("__secure-") and not secure:
            r.add("COOKIE-PREFIX", "low", "Cookie '%s' violates __Secure- prefix rules" % name, evidence,
                  "__Secure- requires the Secure attribute.", "Add Secure.")


CHECKS = [check_hsts, check_csp, check_clickjacking, check_nosniff,
          check_referrer_permissions, check_disclosure, check_cors, check_cookies]


def analyse(text, source="input"):
    resp = parse_response(text)
    report = Report(resp, source)
    if not resp.headers:
        return report
    for check in CHECKS:
        check(report)
    return report


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def summary_counts(report):
    counts = {s: 0 for s in SEVERITIES}
    for f in report.findings:
        counts[f["severity"]] += 1
    return counts


def render_markdown(report):
    r, c = report.resp, summary_counts(report)
    out = ["# HTTP Security Header & Cookie Report", "",
           "- **Source:** %s" % report.source,
           "- **URL:** %s" % (r.url or "(not provided)"),
           "- **Status:** %s" % (r.status if r.status else "(unknown)"),
           "- **Content-Type:** %s" % (report.content_type or "(none)"), "",
           "## Summary", "", "| Severity | Count |", "|---|---|"]
    out += ["| %s | %d |" % (s.capitalize(), c[s]) for s in SEVERITIES]
    out += ["", "## Findings (highest priority first)", ""]
    if not report.findings:
        out.append("_No findings._\n")
    for f in report.sorted_findings():
        out += ["### [%s] %s" % (f["severity"].upper(), f["title"]), "",
                "- **Rule:** `%s`" % f["rule"],
                "- **Evidence:** `%s`" % f["evidence"],
                "- **Why it matters:** %s" % f["why"],
                "- **Fix:** %s" % f["fix"], ""]
    out += ["## Checks intentionally NOT flagged (false-positive handling)", ""]
    out += ["- `%s`: %s" % (s["rule"], s["reason"]) for s in report.skipped] or ["_None._"]
    out += ["", "## Checks passed", ""]
    out += ["- %s" % p for p in report.passed] or ["_None._"]
    if report.notes:
        out += ["", "## Notes", ""] + ["- %s" % n for n in report.notes]
    return "\n".join(out) + "\n"


def render_json(report):
    r = report.resp
    return json.dumps({
        "source": report.source, "url": r.url, "status": r.status,
        "summary": summary_counts(report), "findings": report.sorted_findings(),
        "not_flagged": report.skipped, "passed": report.passed, "notes": report.notes,
    }, indent=2) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline HTTP security header & cookie analyser.")
    ap.add_argument("file", help="saved raw HTTP response (e.g. from curl -i)")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--output", "-o", help="write report to this file instead of stdout")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"],
                    help="exit with code 1 if any finding at/above this severity exists (for CI)")
    args = ap.parse_args(argv)
    path = Path(args.file)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print("error: cannot read %s: %s" % (path, e), file=sys.stderr)
        return 2
    report = analyse(text, path.name)
    if not report.resp.headers:
        print("error: no HTTP headers found in %s" % path, file=sys.stderr)
        return 2
    rendered = render_markdown(report) if args.format == "md" else render_json(report)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    if args.fail_on and any(RANK[f["severity"]] <= RANK[args.fail_on] for f in report.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
