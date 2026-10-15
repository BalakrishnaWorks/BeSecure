# Security policy

## Intended use
BeSecure is intended for local, authorized, low-impact website configuration assessment. The authorization checkbox is a reminder, not proof of legal authority.

## Scope and limitations
The tool does not perform exploit validation, authenticated testing, brute force, form submission, or database access. Authorized Expanded mode performs a bounded same-origin crawl of discoverable HTML pages plus fixed metadata requests. Do not describe its results as a full penetration test or a guarantee that a system is safe to publish.

## Reporting a security issue
Do not include real patient data, credentials, session tokens, or confidential target information in issue reports. Reproduce against a test environment whenever possible.

Expanded mode limits crawling to 25 URLs and depth 2, only follows exact-origin links, removes query parameters/fragments, and never submits forms. Use only under written authorization.
