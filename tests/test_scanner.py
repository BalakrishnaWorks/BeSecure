import unittest
from unittest.mock import patch
from scanner import Finding, ScanError, _PageParser, _same_origin_url, calculate_score, normalize_url, resolve_public_ips

class NormalizeUrlTests(unittest.TestCase):
    def test_adds_https(self): self.assertEqual(normalize_url("example.com"), "https://example.com/")
    def test_rejects_non_http_scheme(self):
        with self.assertRaises(ScanError): normalize_url("file:///etc/passwd")
    def test_rejects_credentials(self):
        with self.assertRaises(ScanError): normalize_url("https://user:pass@example.com")
    def test_rejects_query_and_fragment(self):
        with self.assertRaises(ScanError): normalize_url("https://example.com/?token=secret")
    def test_blocks_localhost(self):
        with self.assertRaises(ScanError): normalize_url("http://localhost")
    def test_blocks_private_ip(self):
        with self.assertRaises(ScanError): normalize_url("http://192.168.1.1")
    def test_blocks_internal_suffix(self):
        with self.assertRaises(ScanError): normalize_url("https://server.internal")

class DnsSafetyTests(unittest.TestCase):
    @patch("scanner.socket.getaddrinfo")
    def test_rejects_private_dns_answer(self, mocked):
        mocked.return_value = [(None, None, None, None, ("127.0.0.1", 443))]
        with self.assertRaises(ScanError): resolve_public_ips("public-looking.example", 443)
    @patch("scanner.socket.getaddrinfo")
    def test_accepts_public_dns_answer(self, mocked):
        mocked.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        self.assertEqual(resolve_public_ips("example.com", 443), ["93.184.216.34"])

class ScoreTests(unittest.TestCase):
    def test_fixed_deductions_and_pass_ignored(self):
        fs = [Finding("a", "a", "High", "Finding", "e", "r"), Finding("b", "b", "Medium", "Finding", "e", "r"), Finding("c", "c", "Low", "Finding", "e", "r"), Finding("d", "d", "Low", "Pass", "e", "r")]
        self.assertEqual(calculate_score(fs)[0], 66)
    def test_score_floors_at_zero(self):
        fs = [Finding(str(i), "x", "Critical", "Finding", "e", "r") for i in range(5)]
        self.assertEqual(calculate_score(fs)[0], 0)
    def test_example_score_68(self):
        fs = [Finding("a", "a", "Medium", "Finding", "e", "r"), Finding("b", "b", "Medium", "Finding", "e", "r"), Finding("c", "c", "Low", "Finding", "e", "r"), Finding("d", "d", "Low", "Finding", "e", "r"), Finding("e", "e", "Low", "Finding", "e", "r"), Finding("f", "f", "Informational", "Finding", "e", "r"), Finding("g", "g", "Informational", "Pass", "e", "r"), Finding("h", "h", "Informational", "Info", "e", "r")]
        self.assertEqual(calculate_score(fs)[0], 68)
        self.assertEqual(sum(f.status == "Finding" for f in fs), 6)
        self.assertEqual(len(fs), 8)

class ExpandedModeSafetyTests(unittest.TestCase):
    def test_only_same_origin_links_are_accepted(self):
        base = "https://example.com/start"
        self.assertEqual(_same_origin_url(base, "/about?private=value#section"), "https://example.com/about")
        self.assertIsNone(_same_origin_url(base, "https://other.example/path"))
        self.assertIsNone(_same_origin_url(base, "http://example.com/insecure"))
        self.assertIsNone(_same_origin_url(base, "https://example.com:444/path"))

    def test_page_parser_inventories_without_submitting_forms(self):
        parser = _PageParser()
        parser.feed('<a href="/about">About</a><script src="/app.js"></script><form action="/login" method="post"><input></form>')
        self.assertEqual(parser.links, ["/about"])
        self.assertEqual(parser.resources, ["/app.js"])
        self.assertEqual(parser.forms, [("/login", "post")])


if __name__ == "__main__": unittest.main(verbosity=2)
