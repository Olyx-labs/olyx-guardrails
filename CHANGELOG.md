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

### Fixed
- `SecretScanner` `redact` action now removes the full matched secret instead
  of only the truncated prefix shown in `findings` — long AWS secret keys,
  tokens, and JWTs were previously left partially exposed in "redacted" output
- `PiiScrubber::CARD_PATTERN` no longer swallows a trailing space or hyphen
  from surrounding text when redacting a card-like number
- `PiiScrubber::CARD_PATTERN` now validates matches against a Luhn checksum
  before redacting, so ordinary numeric IDs (order numbers, timestamps,
  tracking numbers) in the 13-19 digit range are no longer mislabeled `[CARD]`
- `PiiScrubber::PHONE_PATTERN` no longer matches an arbitrary substring of a
  longer digit run; it now requires the full contiguous digit sequence to be
  captured

### Changed
- `Olyx::Guardrails.check` now evaluates the `length` check first and skips
  the `pii`, `injection`, and `secret` scans entirely when input already
  exceeds `max_input_length`, instead of paying their full regex-scanning
  cost before rejecting on size. Previously a 20MB oversized payload took
  ~2.6s to reject even with a tiny `max_input_length`; it now rejects in
  under a millisecond. Skipped checks are marked `skipped: true`.
