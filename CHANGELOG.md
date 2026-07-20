# Changelog

All notable changes to olyx-guardrails are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-07-16

### Changed
- Adopted the Ruby community style guide's comment conventions throughout
  `lib/`: `# frozen_string_literal: true` on every Ruby file, YARD
  `@param`/`@return`/`@raise`/`@example` documentation on all public
  methods, and `REVIEW`/`OPTIMIZE` annotations marking already-documented
  known limitations (regex-only detection coverage, the synchronous Rootly
  network call) directly at their source instead of only in the README.

### Security
- `RootlyNotifier` no longer sends raw, unredacted input in the incident
  "Input preview." Previously, since incidents are only opened on a
  violation, the preview was guaranteed to contain the exact PII or secret
  that triggered the alert — forwarding it in plaintext to a third-party
  API. The preview is now passed through `PiiScrubber.scrub` and
  `SecretScanner.scan(secret_action: "redact")` before truncation.
- `Olyx::Guardrails.check` no longer crashes when an `ai_analyzer:` hook
  returns a non-finite or non-numeric `risk_score` (`NaN`, `Infinity`, an
  Array, a garbage string, etc.). Previously this raised an uncaught
  `ArgumentError`/`NoMethodError` from inside `Float#clamp`, directly
  contradicting the documented "fault-tolerant" guarantee — a single
  malformed LLM response could take down the caller's request. The score is
  now coerced defensively via `Float(value, exception: false)` plus a
  `finite?` check; an unusable value is treated as "no score" rather than
  crashing or silently substituting a number.
- `RootlyNotifier#notify` now wraps payload-building (not just the network
  call) in the same rescue, and normalizes a non-Hash `metadata:` to `{}`,
  so a malformed `result` shape or `metadata: nil` degrades to
  `{ success: false, error: ... }` instead of raising into the caller.
- Fixed gemspec metadata (`homepage`, `source_code_uri`, `changelog_uri`,
  `bug_tracker_uri`) pointing at a nonexistent `olyx-labs/olyx-guardrails`
  repo on a nonexistent `main` branch. Now points at the actual
  `mosesnjoroge/olyx-guardrails` repo on `master`.

### Fixed
- `ai_merge_secret` now sets `count` to at least 1 when the AI hook flags a
  secret the regex scan missed, instead of leaving `leaked: true` alongside
  a stale `count: 0`.
- `test/rootly_notifier_test.rb`'s network-error test previously asserted a
  hand-written literal hash and never actually exercised `post_incident` —
  it would have passed even if the real rescue were removed. It now drives
  the real method against a genuinely refused local connection.

### Added
- `ai_analyzer:` hook on `Olyx::Guardrails.check` — an optional callable that
  receives `(text, context)` and returns an AI-powered evaluation. Enables
  semantic injection detection, intent-aware PII classification, and any
  LLM-backed safety check without adding runtime dependencies to the gem.
  The hook follows defense-in-depth: AI findings union with regex findings —
  the hook can flag additional violations but cannot clear existing ones.
  Exceptions raised by the hook are rescued; the error is surfaced in
  `result[:ai_analysis][:error]` and the regex result stands.
- `result[:ai_analysis]` — present when `ai_analyzer:` is supplied; carries
  the hook's `injection_attempt`, `pii_detected`, `secret_leaked`,
  `risk_score`, and `reason` fields, plus any `error` from a failed call.
- `result[:risk_score]` now takes the maximum of the regex-derived score and
  the hook's `risk_score` when provided, so an AI-assigned high-confidence
  score is never silently downgraded by a lower regex score.
- `Olyx::Guardrails::Integrations::RootlyNotifier` — opens a Rootly incident
  when a guardrail violation is detected. Maps `risk_score` to Rootly severity
  (sev1–sev4), includes violation labels, input preview, AI analysis reason,
  and arbitrary caller metadata in the incident summary. Loaded on demand via
  `require "olyx/guardrails/integrations/rootly_notifier"` — not required by
  the core gem so projects not using Rootly pay no cost.
- `examples/claude_analyzer.rb` — runnable reference implementation of the
  `ai_analyzer:` hook wired to Claude via the Anthropic Ruby SDK.
- `examples/rootly_integration.rb` — end-to-end example: check → Claude
  semantic analysis → Rootly incident on violation.

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
