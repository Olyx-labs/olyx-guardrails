# Changelog

All notable changes to olyx-guardrails are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-07-15

### Added
- `PiiScrubber` — redacts email, SSN, credit card, phone, IPv4, API tokens,
  passport numbers, IBANs, and dates of birth from arbitrary strings and
  message arrays
- `InjectionDetector` — detects prompt injection via structural tags,
  jailbreak phrases, and multi-turn split-attack patterns across adjacent
  message pairs
- `SecretScanner` — detects confidentiality markers, internal endpoints,
  private network addresses, GitHub/GitLab/Slack/npm tokens, AWS access key
  IDs, AWS secret keys, Anthropic keys, and JWT bearer tokens; supports
  `alert`, `redact`, and `block` actions plus custom regex patterns
- Apache-2.0 license
