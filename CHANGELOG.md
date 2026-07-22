# Changelog

All notable changes to olyx-guardrails are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-07-21

Initial public release.

### Decision and transformation

- `Olyx::Guardrails.check` — makes an allow/block decision against PII,
  prompt-injection, secret, and restricted-policy findings without
  transforming the input. Returns `allowed`, per-category detection flags,
  `risk_score`, and a `checks` array with one entry per category. The
  `length` check runs first; content and AI checks are skipped (not just
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
- `ai_failure_mode:` controls how an analyzer failure is handled: `:allow`
  (default, keeps the deterministic result), `:block` (adds a failed `ai`
  check and rejects), or `:raise` (`AiAnalyzerError`).
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

### AI analyzer hook

- Optional `ai_analyzer:` callable receives `(text, context)` and returns a
  Hash or a schema-model object implementing `deep_to_h`/`to_h`. Findings
  can add a violation but cannot clear a deterministic one. Boolean fields
  must be actual `true`/`false` values; non-finite risk scores are ignored
  rather than crashing. Exceptions and malformed responses are bounded under
  `result[:ai_analysis][:error]` and handled per `ai_failure_mode`.
- Optional `Integrations::OpenAIAnalyzer` connector for the official OpenAI
  Ruby SDK: sends a strict `OpenAI::BaseModel` schema through the Responses
  API, consumes the parsed schema-model result, defaults to `store: false`,
  and has no model allowlist — it forwards any String/Symbol model
  identifier and relies on Structured Outputs support as the compatibility
  check. Refusals, API failures, and missing parsed output degrade into the
  same `result[:ai_analysis][:error]` path. The `openai` gem is optional and
  loaded lazily.

### Notifications

- Vendor-neutral `Notifier` dispatches one sanitized, deeply frozen,
  versioned event to named callable handlers. Handlers run synchronously and
  independently — one failure doesn't stop the others, and errors are
  returned per handler rather than raised. Input previews, AI reasons,
  metadata keys/values, and handler errors are bounded and redacted with the
  policy's restricted-content rules and the built-in PII/secret detectors.

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

### Quality and security posture

- No runtime dependencies for the core checks; Rails and the OpenAI SDK are
  both optional and loaded only when used.
- CI enforces RuboCop, a Flog structural-complexity gate (max 10 per
  ordinary method, 60 per class/module, with documented DSL exemptions
  only), and a RubyCritic maintainability gate, alongside the Appraisal
  matrix across Rails 7.2, 8.0, and 8.1.
- Least-privilege, SHA-pinned CI actions; CodeQL and OpenSSF Scorecard
  scanning; a private vulnerability-reporting process (see
  [SECURITY.md](SECURITY.md)).
