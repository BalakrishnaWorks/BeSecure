"""BeSecure: bounded, low-impact website security assessment.

Expanded mode performs same-origin, depth-limited HTML discovery and passive
security observations. It does not exploit vulnerabilities, authenticate, submit
forms, brute-force paths, or access databases.
"""
from __future__ import annotations
import http.client
from html.parser import HTMLParser
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit

APP_VERSION = "1.1.0"
USER_AGENT = f"BeSecure/{APP_VERSION} (authorized website assessment; local operator)"
TIMEOUT_SECONDS = 5
MAX_REDIRECTS = 4
MAX_BODY_BYTES = 65536
MAX_RESPONSE_HEADERS = 100
MAX_HEADER_VALUE = 2048
MAX_EXTRA_ENDPOINTS = 4
MAX_CRAWL_PAGES = 25
MAX_CRAWL_DEPTH = 2
MIN_REQUEST_INTERVAL = 0.35

class ScanError(Exception):
    """Safe, user-displayable scan failure."""

@dataclass
class Finding:
    id: str
    title: str
    severity: str
    status: str
    evidence: str
    recommendation: str
    confidence: str = "High"

@dataclass
class ScanReport:
    target: str
    scanned_at_utc: str
    scanner_version: str
    assessment_mode: str
    score: int
    score_explanation: str
    http_status: int | None
    final_url: str
    checks_completed: int
    findings: list[Finding]
    notes: list[str]
    def to_dict(self) -> dict:
        return asdict(self)
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ScanError("Enter a website domain, such as https://example.com")
    if len(raw) > 2048:
        raise ScanError("The target is too long.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ScanError("The website address is not valid.") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ScanError("Only HTTP and HTTPS website addresses are allowed.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ScanError("Enter a public website hostname without username or password.")
    if parsed.query or parsed.fragment:
        raise ScanError("For safety, enter a domain or path without query parameters or fragments.")
    hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if hostname in {"localhost"} or hostname.endswith((".localhost", ".local", ".internal")):
        raise ScanError("Local and private-network targets are blocked.")
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise ScanError("Private, loopback, link-local, and reserved IP targets are blocked.")
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))

def resolve_public_ips(hostname: str, port: int) -> list[str]:
    """Resolve once and reject any mixed/private/reserved DNS answer."""
    try:
        answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise ScanError("DNS lookup failed. Check the hostname and try again.") from exc
    ips: list[str] = []
    for answer in answers:
        ip_text = answer[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_text.split("%", 1)[0])
        except ValueError as exc:
            raise ScanError("DNS returned an invalid address; scan stopped.") from exc
        if not ip_obj.is_global:
            raise ScanError("This hostname resolves to a private or reserved address; scan blocked.")
        if ip_text not in ips:
            ips.append(ip_text)
    if not ips:
        raise ScanError("DNS did not return a usable public address.")
    return ips

class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, ip: str, port: int, timeout: float):
        super().__init__(hostname, port=port, timeout=timeout)
        self._pinned_ip = ip
    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, ip: str, port: int, timeout: float):
        super().__init__(hostname, port=port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = ip
    def connect(self) -> None:
        raw_sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
        except Exception:
            raw_sock.close()
            raise

def _fetch_once_detailed(url: str, method: str = "GET", capture_body: bool = False) -> tuple[int, dict[str, list[str]], str | None, str | None, str]:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    scheme = parsed.scheme
    port = parsed.port or (443 if scheme == "https" else 80)
    ips = resolve_public_ips(hostname, port)
    last_error: Exception | None = None
    for ip in ips[:4]:
        conn: http.client.HTTPConnection | None = None
        try:
            conn = (_PinnedHTTPSConnection(hostname, ip, port, TIMEOUT_SECONDS) if scheme == "https"
                    else _PinnedHTTPConnection(hostname, ip, port, TIMEOUT_SECONDS))
            path = parsed.path or "/"
            host_header = hostname
            if parsed.port is not None and parsed.port not in (80, 443):
                host_header = f"{hostname}:{parsed.port}"
            conn.request(method, path, headers={
                "Host": host_header, "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                "Connection": "close", "Range": f"bytes=0-{MAX_BODY_BYTES - 1}",
            })
            response = conn.getresponse()
            headers: dict[str, list[str]] = {}
            for key, value in response.getheaders()[:MAX_RESPONSE_HEADERS]:
                headers.setdefault(key.lower(), []).append(value[:MAX_HEADER_VALUE])
            cert_expiry = None
            if scheme == "https" and getattr(conn, "sock", None):
                try:
                    cert_expiry = conn.sock.getpeercert().get("notAfter")
                except (OSError, AttributeError):
                    cert_expiry = None
            location_values = headers.get("location", [])
            location = location_values[0] if location_values else None
            # Read at most MAX_BODY_BYTES. Only the expanded crawler asks for a
            # temporary HTML string; content is never added to the report.
            body_text = ""
            if method != "HEAD":
                raw_body = response.read(MAX_BODY_BYTES)
                content_type = _headers_for(headers, "content-type") or ""
                if capture_body and "html" in content_type.lower():
                    charset = "utf-8"
                    if "charset=" in content_type.lower():
                        charset = content_type.lower().split("charset=", 1)[1].split(";", 1)[0].strip()[:40] or "utf-8"
                    try:
                        body_text = raw_body.decode(charset, errors="replace")
                    except LookupError:
                        body_text = raw_body.decode("utf-8", errors="replace")
            return response.status, headers, cert_expiry, location, body_text
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
            last_error = exc
        finally:
            if conn is not None:
                conn.close()
    if isinstance(last_error, ssl.SSLCertVerificationError):
        raise ScanError("TLS certificate validation failed. The connection was not trusted, so scanning stopped.")
    if isinstance(last_error, ssl.SSLError):
        raise ScanError("The secure connection failed TLS validation or negotiation.")
    raise ScanError("The website could not be reached safely within the time limit.")

def _fetch_once(url: str, method: str = "GET") -> tuple[int, dict[str, list[str]], str | None, str | None]:
    status, headers, cert_expiry, location, _ = _fetch_once_detailed(url, method, False)
    return status, headers, cert_expiry, location


class _PageParser(HTMLParser):
    """Extract only navigational/resource URLs and form metadata; never submit forms."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.resources: list[str] = []
        self.forms: list[tuple[str, str]] = []
        self._in_form = False
        self._form_action = ""
        self._form_method = "get"

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag in {"script", "img", "iframe", "link", "source"}:
            value = attrs.get("src") or (attrs.get("href") if tag == "link" else "")
            if value:
                self.resources.append(value)
        if tag == "form":
            self._in_form = True
            self._form_action = attrs.get("action", "")
            self._form_method = (attrs.get("method", "get") or "get").lower()
            self.forms.append((self._form_action, self._form_method))

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._in_form = False


def _same_origin_url(base_url: str, candidate: str) -> str | None:
    """Return a normalized same-origin URL, or None; discard query/fragment data."""
    try:
        joined = urljoin(base_url, candidate)
        parsed = urlsplit(joined)
        base = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != base.hostname:
            return None
        if (parsed.port or (443 if parsed.scheme == "https" else 80)) != (base.port or (443 if base.scheme == "https" else 80)):
            return None
        if base.scheme == "https" and parsed.scheme != "https":
            return None
        path = parsed.path or "/"
        # Ignore non-page fragments and query parameters; never send them.
        normalized = normalize_url(urlunsplit((parsed.scheme, parsed.netloc, path, "", "")))
        return normalized
    except (ScanError, ValueError):
        return None


def _fetch_html_with_redirects(start_url: str) -> tuple[str, int, dict[str, list[str]], str]:
    origin_host = urlsplit(start_url).hostname
    current = start_url
    for redirects in range(MAX_REDIRECTS + 1):
        status, headers, _, location, body = _fetch_once_detailed(current, "GET", True)
        if status in {301, 302, 303, 307, 308} and location:
            if redirects >= MAX_REDIRECTS:
                raise ScanError("Redirect limit reached while discovering pages.")
            next_url = normalize_url(urljoin(current, location))
            parts = urlsplit(next_url)
            if parts.hostname != origin_host or (urlsplit(current).scheme == "https" and parts.scheme != "https"):
                raise ScanError("Cross-host or HTTPS downgrade redirect blocked during page discovery.")
            current = next_url
            continue
        return current, status, headers, body
    raise ScanError("Redirect limit reached while discovering pages.")


def _headers_for(headers: dict[str, list[str]], name: str) -> str | None:
    values = headers.get(name.lower())
    return ", ".join(values) if values else None

def evaluate_findings(final_url: str, status: int, headers: dict[str, list[str]]) -> list[Finding]:
    findings: list[Finding] = []
    final = urlsplit(final_url)
    is_https = final.scheme == "https"
    hsts = _headers_for(headers, "strict-transport-security")
    csp = _headers_for(headers, "content-security-policy")
    xfo = _headers_for(headers, "x-frame-options")
    xcto = _headers_for(headers, "x-content-type-options")
    referrer = _headers_for(headers, "referrer-policy")
    permissions = _headers_for(headers, "permissions-policy")
    if not is_https:
        findings.append(Finding("transport-https", "Website did not finish on HTTPS", "High", "Finding",
            f"Final response URL scheme is {final.scheme.upper()}.",
            "Serve the site over HTTPS and redirect HTTP requests to HTTPS."))
    else:
        findings.append(Finding("transport-https", "HTTPS is used", "Informational", "Pass",
            "The final response URL uses HTTPS and TLS certificate validation succeeded.",
            "Keep TLS configuration and certificate renewal monitored."))
        if not hsts:
            findings.append(Finding("header-hsts", "HSTS header not observed", "Medium", "Finding",
                "Strict-Transport-Security was absent from the response headers.",
                "Consider enabling HSTS after confirming all relevant subdomains support HTTPS."))
        else:
            findings.append(Finding("header-hsts", "HSTS header observed", "Informational", "Pass",
                f"Strict-Transport-Security: {hsts[:500]}", "Review max-age and subdomain scope."))
    checks = [
        ("header-csp", "Content Security Policy not observed", "Medium", csp,
         "Content-Security-Policy was absent from the response headers.",
         "Define an application-appropriate CSP; test report-only before enforcement."),
        ("header-nosniff", "MIME-sniffing protection not observed", "Low", xcto,
         "X-Content-Type-Options was absent from the response headers.", "Consider X-Content-Type-Options: nosniff."),
        ("header-framing", "Clickjacking protection not observed", "Low",
         xfo or ("CSP frame-ancestors" if csp and "frame-ancestors" in csp.lower() else None),
         "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
         "Set an appropriate CSP frame-ancestors directive; consider X-Frame-Options for legacy support."),
        ("header-referrer", "Referrer policy not observed", "Low", referrer,
         "Referrer-Policy was absent from the response headers.", "Choose a suitable Referrer-Policy for the application."),
        ("header-permissions", "Permissions Policy not observed", "Informational", permissions,
         "Permissions-Policy was absent from the response headers.", "Consider restricting browser features the application does not need."),
    ]
    for fid, title, severity, value, evidence, recommendation in checks:
        findings.append(Finding(fid, title if not value else title.replace("not observed", "observed"),
            "Informational" if value else severity, "Pass" if value else "Finding",
            f"Observed: {value[:500]}" if value else evidence, recommendation))
    cookie_headers = headers.get("set-cookie", [])
    if cookie_headers:
        insecure = []
        for raw in cookie_headers[:20]:
            parts = [p.strip().lower() for p in raw.split(";")[1:]]
            attrs = []
            if "secure" not in [p.split("=", 1)[0] for p in parts]: attrs.append("Secure")
            if "httponly" not in [p.split("=", 1)[0] for p in parts]: attrs.append("HttpOnly")
            if not any(p.startswith("samesite=") for p in parts): attrs.append("SameSite")
            if attrs: insecure.append(", ".join(attrs))
        if insecure:
            findings.append(Finding("cookie-flags", "Some cookies may lack security attributes", "Medium", "Finding",
                f"Security attributes missing on {len(insecure)} of {min(len(cookie_headers), 20)} inspected Set-Cookie headers; cookie values were not retained.",
                "Review cookie purpose and apply Secure, HttpOnly, and suitable SameSite attributes where appropriate."))
        else:
            findings.append(Finding("cookie-flags", "Observed cookies include common security attributes", "Informational", "Pass",
                f"The first {min(len(cookie_headers), 20)} Set-Cookie headers included common attributes.",
                "Confirm attributes are suitable for each cookie and flow."))
    else:
        findings.append(Finding("cookie-flags", "No Set-Cookie headers observed", "Informational", "Info",
            "The inspected response did not include Set-Cookie headers; client-side and other routes were not assessed.",
            "Review cookies on application-specific routes during an authorized deeper assessment."))
    if status >= 500:
        findings.append(Finding("http-status", "Server returned an error status", "Informational", "Info",
            f"HTTP status was {status}; one response cannot establish the cause.",
            "Review server-side logs internally and avoid exposing sensitive error details."))
    return findings

def calculate_score(findings: Iterable[Finding]) -> tuple[int, str]:
    deductions = {"Critical": 30, "High": 20, "Medium": 10, "Low": 4}
    # A repeated issue on many pages is one control gap for the heuristic score;
    # the report evidence still lists multiple affected routes.
    unique = {}
    for finding in findings:
        if finding.status == "Finding":
            unique.setdefault((finding.id, finding.severity), finding)
    total = sum(deductions.get(f.severity, 0) for f in unique.values())
    explanation = ("Starts at 100; subtracts 30 per Critical, 20 per High, 10 per Medium, and 4 per Low finding. "
                   "Pass and informational observations do not change the score. This limited heuristic is not a probability of compromise or a certification.")
    return max(0, 100 - total), explanation

def _follow_main_redirects(start_url: str) -> tuple[str, int, dict[str, list[str]], str | None, int]:
    original_host = (urlsplit(start_url).hostname or "").lower()
    current = start_url
    redirects = 0
    while True:
        status, headers, cert_expiry, location = _fetch_once(current, "GET")
        if status in {301, 302, 303, 307, 308} and location:
            if redirects >= MAX_REDIRECTS:
                raise ScanError("Redirect limit reached; scan stopped.")
            next_url = normalize_url(urljoin(current, location))
            next_parts = urlsplit(next_url)
            if (next_parts.hostname or "").lower() != original_host:
                raise ScanError("Redirect to a different hostname was blocked for safety.")
            if urlsplit(current).scheme == "https" and next_parts.scheme != "https":
                raise ScanError("HTTPS-to-HTTP redirect was blocked for safety.")
            current = next_url
            redirects += 1
            continue
        return current, status, headers, cert_expiry, redirects

def scan_website(raw_target: str, mode: str = "passive") -> ScanReport:
    if mode not in {"passive", "authorized"}:
        raise ScanError("Unknown assessment mode.")
    started = time.monotonic()
    start_url = normalize_url(raw_target)
    final_url, status, final_headers, cert_expiry, redirects = _follow_main_redirects(start_url)
    findings = evaluate_findings(final_url, status, final_headers)
    notes = [
        "This is a bounded automated assessment, not a complete penetration test or release approval.",
        "DNS results must be public; connections are pinned to validated IP addresses to reduce DNS-rebinding/SSRF risk.",
        "Cross-host redirects and HTTPS-to-HTTP redirects are blocked. Request timeouts and response sizes are bounded.",
        "Response content is not stored in reports. Expanded mode temporarily parses limited HTML to discover same-origin links and form metadata; forms are never submitted.",
        "No authentication, exploit payloads, brute-force guessing, destructive tests, database access, or patient-data collection is performed.",
        f"Main request returned HTTP {status}; 206 Partial Content can be expected when a server honors the scanner's Range request.",
    ]
    checks_completed = len(findings)
    if cert_expiry:
        notes.append(f"TLS certificate notAfter value from the validated connection: {cert_expiry}.")

    if mode == "authorized":
        # Depth-limited, same-origin crawling of discoverable HTML pages only.
        from collections import deque
        origin = urlsplit(final_url)
        queue = deque([(final_url, 0)])
        visited: set[str] = set()
        page_observations: dict[tuple[str, str, str], dict[str, object]] = {}
        discovered_forms = 0
        discovered_resources = 0
        mixed_content: set[str] = set()
        external_form_actions: set[str] = set()
        crawled_paths: list[str] = []
        while queue and len(visited) < MAX_CRAWL_PAGES:
            page_url, depth = queue.popleft()
            if page_url in visited:
                continue
            visited.add(page_url)
            time.sleep(MIN_REQUEST_INTERVAL)
            try:
                landed_url, page_status, page_headers, html = _fetch_html_with_redirects(page_url)
            except ScanError:
                notes.append(f"Page discovery could not safely fetch {urlsplit(page_url).path or '/'}; remaining checks continued where possible.")
                continue
            if urlsplit(landed_url).hostname != origin.hostname:
                continue
            crawled_paths.append(urlsplit(landed_url).path or "/")
            checks_completed += 1
            content_type = _headers_for(page_headers, "content-type") or ""
            if "html" not in content_type.lower():
                continue
            parser = _PageParser()
            try:
                parser.feed(html)
            except Exception:
                notes.append(f"HTML parsing was incomplete for {urlsplit(landed_url).path or '/'}.")
            discovered_forms += len(parser.forms)
            discovered_resources += len(parser.resources)
            page_findings = evaluate_findings(landed_url, page_status, page_headers)
            path_label = urlsplit(landed_url).path or "/"
            for finding in page_findings:
                key = (finding.id, finding.status, finding.title)
                entry = page_observations.setdefault(key, {"finding": finding, "paths": []})
                paths = entry["paths"]
                if path_label not in paths and len(paths) < MAX_CRAWL_PAGES:
                    paths.append(path_label)
            for resource in parser.resources:
                resolved = urljoin(landed_url, resource)
                rp = urlsplit(resolved)
                if origin.scheme == "https" and rp.scheme == "http":
                    mixed_content.add((urlsplit(landed_url).path or "/") + " -> " + (rp.hostname or "unknown") + (rp.path or "/"))
            for action, method in parser.forms:
                if action:
                    resolved = urljoin(landed_url, action)
                    ap = urlsplit(resolved)
                    if ap.scheme != "https" and origin.scheme == "https":
                        external_form_actions.add((urlsplit(landed_url).path or "/") + " -> non-HTTPS form action")
                    elif ap.hostname != origin.hostname:
                        external_form_actions.add((urlsplit(landed_url).path or "/") + " -> external form action")
            if depth < MAX_CRAWL_DEPTH:
                for href in parser.links:
                    candidate = _same_origin_url(landed_url, href)
                    if candidate and candidate not in visited and candidate not in queue and len(visited) + len(queue) < MAX_CRAWL_PAGES:
                        queue.append((candidate, depth + 1))

        # Merge identical observations across pages so scores do not multiply just
        # because the same missing header appears on many routes.
        for (fid, finding_status, title), entry in page_observations.items():
            finding = entry["finding"]
            paths = entry["paths"]
            finding.evidence = finding.evidence + " Affected/observed paths: " + ", ".join(paths[:8])
            if len(paths) > 8:
                finding.evidence += f" and {len(paths) - 8} more"
            findings.append(finding)
        findings.append(Finding("expanded-crawl-summary", "Bounded same-origin page discovery completed", "Informational", "Info",
            f"Visited {len(visited)} unique URLs; inspected {len(crawled_paths)} HTML pages at depth up to {MAX_CRAWL_DEPTH}. Forms inventoried: {discovered_forms}; resource references observed: {discovered_resources}. Page limit: {MAX_CRAWL_PAGES}.",
            "Compare discovered routes with the application's official route inventory. This crawler cannot see unlinked, authenticated, client-rendered, or blocked pages."))
        if mixed_content:
            examples = sorted(mixed_content)[:8]
            findings.append(Finding("expanded-mixed-content", "HTTP resources referenced by HTTPS pages", "Medium", "Finding",
                f"Observed {len(mixed_content)} HTTP resource reference(s), examples: " + "; ".join(examples),
                "Serve scripts, stylesheets, frames, and other resources over HTTPS; manually verify whether each reference is active content."))
        else:
            findings.append(Finding("expanded-mixed-content", "No HTTP resource references observed in inspected HTML", "Informational", "Info",
                f"No HTTP resource references were found in the {len(crawled_paths)} inspected HTML pages. This does not assess runtime-loaded resources.",
                "Use browser developer tools and a full application test to check resources loaded dynamically."))
        if external_form_actions:
            findings.append(Finding("expanded-form-actions", "Review form submission destinations", "Medium", "Finding",
                "Form action review flagged: " + "; ".join(sorted(external_form_actions)[:8]),
                "Verify every form action is intentional and uses HTTPS. No forms were submitted."))
        else:
            findings.append(Finding("expanded-form-actions", "No suspicious form action pattern observed", "Informational", "Info",
                f"Inventoried {discovered_forms} form(s); no non-HTTPS or cross-origin explicit form action was observed.",
                "Review form destinations and CSRF controls manually; this check does not establish that forms are secure."))
        notes.append(f"Authorized Expanded inspected {len(crawled_paths)} HTML pages (limit {MAX_CRAWL_PAGES}, depth {MAX_CRAWL_DEPTH}) and inventoried forms without submitting them.")
        notes.append("This bounded crawl only sees pages linked from the starting page or other discovered pages. It does not cover authenticated pages, unlinked routes, APIs requiring credentials, business logic, source/dependency vulnerabilities, or backend/database controls.")

        # Keep the earlier fixed metadata checks as well.
        extra_paths = [("OPTIONS", "/", "HTTP OPTIONS method metadata"),
                       ("GET", "/.well-known/security.txt", "security.txt metadata"),
                       ("GET", "/robots.txt", "robots.txt metadata"),
                       ("GET", "/sitemap.xml", "sitemap.xml metadata")]
        for method, path, label in extra_paths[:MAX_EXTRA_ENDPOINTS]:
            time.sleep(MIN_REQUEST_INTERVAL)
            probe_url = urlunsplit((origin.scheme, origin.netloc, path, "", ""))
            try:
                probe_status, probe_headers, _, probe_location = _fetch_once(probe_url, method)
                checks_completed += 1
                if method == "OPTIONS":
                    allow = _headers_for(probe_headers, "allow")
                    if allow:
                        risky = [m for m in ("TRACE", "CONNECT") if m in {x.strip().upper() for x in allow.split(",")}]
                        if risky:
                            findings.append(Finding("expanded-options", "Review advertised HTTP methods", "Low", "Finding",
                                f"OPTIONS returned an Allow header listing: {', '.join(risky)}. This does not prove the methods are exploitable.",
                                "Verify the methods against server configuration and disable unneeded methods."))
                        else:
                            findings.append(Finding("expanded-options", "HTTP OPTIONS metadata observed", "Informational", "Info",
                                f"Allow header: {allow[:300]}", "Confirm only required methods are enabled."))
                    else:
                        findings.append(Finding("expanded-options", "HTTP OPTIONS metadata unavailable", "Informational", "Info",
                            f"OPTIONS returned HTTP {probe_status}; no Allow header was observed.", "Review allowed methods in server configuration if needed."))
                else:
                    findings.append(Finding("expanded-" + method.lower() + path.replace("/", "-").replace(".", ""),
                        f"{label} endpoint checked", "Informational", "Info",
                        f"The fixed endpoint returned HTTP {probe_status}. Response body was not retained." + (" It returned a redirect that was not followed." if probe_location else ""),
                        "Confirm that published metadata is intentional and does not reveal sensitive internal details."))
            except ScanError:
                checks_completed += 1
                findings.append(Finding("expanded-probe", f"{label} check could not complete", "Informational", "Info",
                    "The bounded request did not complete safely; no response body was retained.",
                    "Review manually within the approved test scope."))

    score, explanation = calculate_score(findings)
    notes.append(f"Completed in {time.monotonic() - started:.1f} seconds. Request timing varies by network and target.")
    return ScanReport(target=start_url, scanned_at_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        scanner_version=APP_VERSION, assessment_mode=mode, score=score, score_explanation=explanation,
        http_status=status, final_url=final_url, checks_completed=checks_completed, findings=findings, notes=notes)

