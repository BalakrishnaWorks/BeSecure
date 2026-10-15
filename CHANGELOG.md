# Changelog

## 1.1.0
- Expanded mode now performs bounded same-origin HTML page discovery (up to 25 URLs, depth 2).
- Added per-page security header/cookie observations, form destination inventory, resource reference inventory, and HTTP-resource references on HTTPS pages.
- Form submissions, authentication, exploit payloads, brute-force discovery, and database access remain out of scope.
- Repeated missing-control observations are merged by control and affected paths to avoid inflating the score.
- Increased temporary response-body cap to 64 KiB for limited HTML parsing; response content is not included in exported reports.
- Added scope-boundary and HTML-parser tests.

## 1.0.0
- Initial enterprise desktop app with Public Surface and fixed metadata-check modes.
