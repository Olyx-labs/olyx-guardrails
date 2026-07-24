# Security Policy

## Supported versions

Security fixes are provided for the latest released minor version. Users should
upgrade to the latest patch release before reporting an issue.

| Version | Supported |
|---|---|
| 1.1.x | Yes |
| <= 1.0 | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use a
[private GitHub security advisory](https://github.com/Olyx-labs/olyx-guardrails/security/advisories/new)
or email `mosesnjoroge@olyxai.io` with:

- the affected version and component;
- reproduction steps or a minimal proof of concept;
- expected and observed behavior;
- the potential confidentiality, integrity, or availability impact; and
- any suggested remediation or disclosure constraints;
- whether the issue is already public; and
- a secure contact method for follow-up.

You should receive an acknowledgement within three business days and an initial
assessment within seven business days. We will coordinate remediation and
disclosure with the reporter.

## Response process

After triage, the maintainer will:

1. confirm the affected supported versions and severity;
2. reproduce the issue using synthetic data;
3. develop a fix and adversarial regression test in private;
4. prepare release notes and upgrade guidance;
5. publish a patched gem; and
6. disclose the issue after supported users can upgrade.

Timelines after the initial assessment depend on severity, exploitability, and
release coordination. The reporter receives material status changes through
the private reporting channel.

## Safe research

Good-faith research must use systems and data the researcher owns or has
permission to test. Do not access another person's data, degrade a service,
perform denial-of-service testing, use social engineering, or publicly disclose
an unpatched issue. Reports that follow these boundaries will not be pursued
for accidental, non-destructive violations of this policy.

## Scope notes

Pattern-based guardrails are defense-in-depth controls, not complete semantic
security boundaries. Documented detection limitations alone are not
vulnerabilities, but bypasses of a documented invariant—especially redaction,
blocking, or third-party data-egress guarantees—are in scope.
