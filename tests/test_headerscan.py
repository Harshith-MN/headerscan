import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import headerscan as hs  # noqa: E402


def run(name):
    text = (ROOT / "samples" / name).read_text(encoding="utf-8")
    rep = hs.analyse(text, name)
    return rep, {f["rule"] for f in rep.findings}, {s["rule"] for s in rep.skipped}


class TestSuccess(unittest.TestCase):
    def test_vulnerable_sample_detects_core_issues(self):
        _, rules, _ = run("vulnerable.txt")
        for expected in ("COOKIE-NO-SECURE", "COOKIE-NO-HTTPONLY", "CSP-UNSAFE-INLINE",
                         "CSP-UNSAFE-EVAL", "CORS-WILDCARD-CREDS", "HSTS-SHORT",
                         "DISCLOSE-SERVER", "COOKIE-SAMESITE-NONE-INSECURE", "COOKIE-PREFIX"):
            self.assertIn(expected, rules)

    def test_hardened_sample_has_no_findings(self):
        rep, rules, _ = run("hardened.txt")
        self.assertEqual(rules, set())


class TestFalsePositives(unittest.TestCase):
    def test_unsafe_inline_ignored_when_nonce_present(self):
        _, rules, skipped = run("hardened.txt")
        self.assertNotIn("CSP-UNSAFE-INLINE", rules)
        self.assertIn("CSP-UNSAFE-INLINE", skipped)

    def test_xfo_not_required_with_frame_ancestors(self):
        _, rules, skipped = run("hardened.txt")
        self.assertNotIn("XFO-MISSING", rules)
        self.assertIn("XFO-MISSING", skipped)

    def test_json_api_not_asked_for_csp_or_xfo(self):
        _, rules, skipped = run("json_api.txt")
        self.assertFalse({"CSP-MISSING", "XFO-MISSING"} & rules)
        self.assertIn("CORS-WILDCARD", skipped)

    def test_http_response_does_not_demand_hsts_or_secure(self):
        _, rules, skipped = run("http_only.txt")
        self.assertNotIn("HSTS-MISSING", rules)
        self.assertIn("HSTS-MISSING", skipped)
        self.assertNotIn("COOKIE-NO-SECURE", rules)

    def test_csrf_cookie_httponly_not_flagged(self):
        _, rules, skipped = run("vulnerable.txt")
        self.assertIn("COOKIE-NO-HTTPONLY:XSRF-TOKEN", skipped)

    def test_server_without_version_not_flagged(self):
        _, rules, skipped = run("json_api.txt")
        self.assertNotIn("DISCLOSE-SERVER", rules)


class TestRobustness(unittest.TestCase):
    def test_last_response_after_redirect_is_analysed(self):
        text = ("# URL: https://x.test/\nHTTP/1.1 301 Moved\nLocation: /home\n\n"
                "HTTP/1.1 200 OK\nContent-Type: text/html\nX-Content-Type-Options: nosniff\n")
        rep = hs.analyse(text)
        self.assertEqual(rep.resp.status, 200)

    def test_cookie_values_never_in_report(self):
        rep, _, _ = run("vulnerable.txt")
        self.assertNotIn("dummyvalue1", hs.render_markdown(rep))
        self.assertNotIn("dummyvalue1", hs.render_json(rep))

    def test_empty_input_has_no_headers(self):
        self.assertFalse(hs.analyse("just some text\n").resp.headers)

    def test_samples_match_expected_output(self):
        for n in ("vulnerable", "hardened", "json_api", "http_only"):
            rep, _, _ = run(n + ".txt")
            exp = (ROOT / "samples" / (n + ".expected.md")).read_text(encoding="utf-8")
            self.assertEqual(hs.render_markdown(rep), exp)


if __name__ == "__main__":
    unittest.main()
