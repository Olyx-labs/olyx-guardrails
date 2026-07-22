# Security Policy

## Supported versions

Security fixes are provided for the latest released minor version. Users should
upgrade to the latest patch release before reporting an issue.

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Email `security@olyxai.io` with:

- the affected version and component;
- reproduction steps or a minimal proof of concept;
- expected and observed behavior;
- the potential confidentiality, integrity, or availability impact; and
- any suggested remediation or disclosure constraints.

You should receive an acknowledgement within three business days and an initial
assessment within seven business days. We will coordinate remediation and
disclosure with the reporter. Please avoid accessing data that is not yours,
degrading services, or publicly disclosing the issue before a fix is available.

## Scope notes

Pattern-based guardrails are defense-in-depth controls, not complete semantic
security boundaries. Documented detection limitations alone are not
vulnerabilities, but bypasses of a documented invariant—especially redaction,
blocking, or third-party data-egress guarantees—are in scope.
