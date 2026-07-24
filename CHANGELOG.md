# Changelog

All notable changes to olyx-guardrails are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] - 2026-07-23

### Changed

- Rails metadata now validates consistently as a Hash at every facade and
  adapter boundary.
- Blocking exceptions use boundary-neutral wording, Active Job selectors
  validate when declared, and inherited job declarations remain effective.
- Notifier misuse raises `ArgumentError`; `nil` now means only that a valid
  decision has zero risk.
- The Rails generator provides copyable policy customization instructions and
  tests the customized YAML path.
- Contributor setup, complete local quality validation, and maintainer release
  verification have canonical commands and documentation.
- Closely coupled proxy objects were folded into their owning runtime,
  configuration, result-building, and notification components.
- Provider risk scores now require a finite Numeric value; numeric strings are
  ignored instead of being coerced across the untrusted provider boundary.
- Contributor and Rails appraisal locks use the current `net-imap` patch.
- CI refreshes the Ruby advisory database and blocks known-vulnerable locked
  dependencies without making the offline local quality gate network-dependent.

## [1.0.0] - 2026-07-21

Initial public release.

### Decision and transformation

- `Olyx::Guardrails.check` — makes an allow/block decision against PII,
  prompt-injection, secret, and restricted-policy findings without
  transforming the input. Returns `allowed`, per-category detection flags,
  `risk_score`, and a `checks` array with one entry per category. The
  `length` check runs first; content and LLM checks are skipped (not just
  failed) when it does, so an oversized payload never pays their cost.
- `Olyx::Guardrails.redact` — transforms text by removing every
  regex-detected PII, secret, and restricted-policy match, without making an
  allow/block decision. Findings expose a masked value, a short SHA-256
  fingerprint, and source offsets — never plaintext credentials. Raises
  `ArgumentError` on oversized input rather than running an unbounded
  transformation.
- `check_messages` adds adjacent `user` → `assistant` multi-turn injection
  detection over structured chat messages. `check_output`/`redact_output`
  are explicit aliases for the completed-output boundary, distinct from
  input checks so applications can instrument both without implying
  streaming-token enforcement.

### Policy

- Immutable `Policy` and `PolicyRule` configuration: named blocking or
  monitoring-only restricted-content rules, `substring`/`whole_word`/`regexp`
  term matching, case-aware regex support, configurable safe replacements,
  and `Policy.from_h` for YAML/JSON-style Hash loading.
- `llm_failure_mode:` controls how a provider failure is handled: `:allow`
  (default, keeps the deterministic result), `:block` (adds a failed `llm`
  check and rejects), or `:raise` (`LlmProviderError`).
- Invalid configuration — duplicate rule names, empty-matching or invalid
  patterns, malformed message arrays, invalid custom regexes — raises
  `ArgumentError` at construction time rather than silently degrading into a
  permissive policy.

### Detection

- `PiiScrubber` recognizes email, formatted/international phone,
  structurally valid U.S. SSN, Luhn-valid Canadian SIN, Luhn-valid payment
  card, valid IPv4/IPv6, token prefixes, contextualized passports,
  formatted/checksum-valid IBAN, and calendar-valid contextualized dates of
  birth.
- `InjectionDetector` matches structural tags, jailbreak phrases, and
  adjacent-turn split attacks against bounded variants produced by NFKC
  normalization, common Greek/Cyrillic homoglyph folding, zero-width
  removal, and one decoding layer each for URL, HTML-entity, Unicode-escape,
  and Base64 encoding.
- `SecretScanner` detects common cloud/SaaS tokens, JWTs, PEM private keys,
  credential-bearing database URLs, confidentiality markers, and private
  network endpoints via explicit `scan` (detect), `redact` (transform), and
  `scan!` (raise `Blocked`) operations. A confidentiality marker redacts the
  complete input, since the marker alone doesn't identify the sensitive
  span. Custom patterns extend detection and are classified as secrets; use
  `PolicyRule` for named business restrictions instead.

### LLM provider hook

- Optional `llm_provider:` callable receives `(text, context)` and returns a
  Hash or a schema-model object implementing `deep_to_h`/`to_h`. Findings
  can add a violation but cannot clear a deterministic one. Boolean fields
  must be actual `true`/`false` values; non-finite risk scores are ignored
  rather than crashing. Exceptions and malformed responses are bounded under
  `result[:llm_analysis][:error]` and handled per `llm_failure_mode`.
- Provider transport is application-owned. The gem has no vendor SDK adapters,
  endpoint assumptions, model allowlists, or model-specific parameters.
  A framework-free local HTTP example demonstrates an open-source-first
  classifier boundary using only Ruby standard-library HTTP and JSON support.

### Notifications

- Vendor-neutral `Notifier` dispatches one sanitized, deeply frozen,
  versioned event to named callable handlers. Handlers run synchronously and
  independently — one failure doesn't stop the others, and errors are
  returned per handler rather than raised. Input previews, LLM reasons,
  metadata keys/values, and handler errors are bounded and redacted with the
  policy's restricted-content rules and the built-in PII/secret detectors.
- Notification events expose optional provider reasoning as `llm_reason`;
  the pre-release `ai_reason` field is not retained.

### Rails integration

- Optional first-class Rails adapter, absent from the core runtime
  dependency set: a Railtie with boot-finalized configuration, safe
  environment-keyed YAML policy loading (`YAML.safe_load`, no ERB/aliases/
  arbitrary classes), an install generator, and explicit opt-in boundary
  adapters for controllers, GraphQL, Action Cable, Active Job arguments,
  Active Model validation, caller-extracted uploads, and service objects
  (`Rails::Enforcer`).
- Content-free Active Support instrumentation (`check`, `violation`,
  `redact`, `notification` events) carries bounded decision/delivery fields
  and duration only — never raw input, redacted output, metadata, or
  analyzer prose. Subscriber failures are isolated from enforcement.
- `Rails::ActiveJobHandler` enqueues sanitized notification events through
  any Active Job backend, resolving a reload-safe String/Symbol job
  constant at delivery time.
- The initial compatibility window covers Rails 8.0 and 8.1. Only listed Rails
  series are tested and supported; subsequent gem releases may remove a series
  after its upstream security support ends.

### Quality and security posture

- The core has one lightweight runtime dependency, Ruby's `base64` bundled gem.
  Rails remains optional and is loaded only when used.
- CI enforces RuboCop — including calibrated structural-complexity cops
  (`Metrics/AbcSize`, `CyclomaticComplexity`, `PerceivedComplexity`,
  `ClassLength`) in place of a separate complexity tool — and a RubyCritic
  maintainability gate, alongside the Appraisal matrix across Rails 8.0
  and 8.1.
- Native RDoc covers every supported public class, module, constant, attribute,
  and method. CI blocks undocumented additions to the explicit public API
  manifest while leaving implementation-only constants outside the
  compatibility contract.
- Least-privilege, SHA-pinned CI actions; CodeQL and OpenSSF Scorecard
  scanning; a private vulnerability-reporting process (see
  [SECURITY.md](SECURITY.md)).
