# BeSecure Enterprise v1.1.0

A local Windows desktop app for bounded website security assessment. Python 3.11+ recommended. No third-party Python packages are required for normal use.

## Modes

### Public Surface
- HTTPS/TLS validation and final URL
- HSTS, CSP, X-Content-Type-Options, framing, Referrer-Policy and Permissions-Policy observations
- Observable Set-Cookie attribute checks (cookie values are not reported)
- Same-host redirects only; HTTPS-to-HTTP redirects are blocked

### Authorized Expanded
Adds a bounded, same-origin crawl of HTML pages discovered through links, up to 25 unique URLs and depth 2. For each discovered HTML page, it observes security headers and cookie attributes, inventories form destinations and resource references without submitting forms, flags observed HTTP resource references on HTTPS pages, and checks fixed metadata endpoints (`OPTIONS /`, `/.well-known/security.txt`, `/robots.txt`, `/sitemap.xml`).

This is intentionally low-impact: it uses GET/OPTIONS requests only, bounded response reads, request delays, and same-origin scope enforcement. It does not log in, submit forms, send exploit payloads, fuzz inputs, brute-force paths, test account access, or connect to databases. It cannot test every URL, API, authenticated workflow, client-rendered route, business-logic path, source-code dependency, or backend control. It is **not a full penetration test**.

## Windows setup
1. Install Python from https://www.python.org/downloads/windows/ and enable PATH.
2. Extract the ZIP.
3. Open Command Prompt in the extracted `besecure` directory.
4. Run tests: `py -m unittest discover -s tests -v`
5. Launch: `py app.py`

## Safety and privacy
- Authorization checkbox required for either mode.
- Public/global IP validation; mixed or private DNS answers are rejected.
- TCP connections are pinned to validated IP addresses; TLS certificate and hostname validation remain enabled.
- Requests have timeouts, bounded headers/body reads, a redirect limit, crawl depth/page caps, and request delays.
- Cross-host redirects and HTTPS downgrade redirects are blocked. Discovered links are restricted to the exact origin (scheme/host/port). Query parameters and fragments are removed before crawling.
- Expanded mode temporarily parses a bounded HTML response in memory to discover links/forms/resources. Page contents are not written to the report; forms are never submitted. Cookie values are not included in findings.
- No telemetry, account, database connection, patient data, API keys, or external scanning service. Reports are only saved when the user explicitly exports JSON.

## Scoring and verdicts
The score is a transparent presentation heuristic, not a probability of compromise or an industry-standard rating. Repeated observations of the same missing control across pages do not multiply the score deduction. A high score or no findings does not mean the site is safe to publish. Use the results alongside manual testing and independent review.

## Before a healthcare company uses it
Treat this as an evaluation prototype. Require independent code/security review, threat modeling, broader integration tests, approved test scope and maintenance windows, deployment hardening, signed release artifacts, and legal/privacy review. Do not run any scanner against production healthcare systems without written system-owner authorization and change-management approval. Use a staging environment and synthetic data for deeper testing.
