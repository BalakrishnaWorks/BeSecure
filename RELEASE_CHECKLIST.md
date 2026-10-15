# Healthcare vendor evaluation checklist

This checklist is for the receiving company's security team. BeSecure does not automatically approve a release.

- [ ] Confirm written authorization and exact hostnames/IP ranges in scope.
- [ ] Confirm the test window and change-management approval, especially for production.
- [ ] Review this source code and dependencies; independently assess SSRF, DNS rebinding, redirect handling, resource limits, and report handling.
- [ ] Test in a non-production environment before any production use.
- [ ] Perform authenticated application testing with an approved specialist tool/process where required.
- [ ] Review source code, dependency vulnerabilities, secrets, identity/access controls, logging, backup/recovery, and data flows separately.
- [ ] Complete healthcare privacy, compliance, and legal review as applicable to the company's jurisdiction and services.
- [ ] Validate all findings manually and document false positives and accepted risks.
- [ ] Require an authorized security professional to make the final release decision.
- [ ] Store exported reports according to the company's confidentiality and retention policies.

A clean BeSecure report is not evidence that the entire application is secure or safe to publish.

- [ ] Confirm bounded crawl stays within the exact authorized origin and does not submit forms.
- [ ] Validate crawler behavior on representative static, SPA, and authenticated test applications.
- [ ] Review report accuracy and false-positive handling before use for release decisions.
