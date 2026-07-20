# Olyx Guardrails

`olyx-guardrails` is a dependency-light Ruby library for synchronous AI input
safety:

- PII and credential redaction
- Prompt-injection and jailbreak detection
- Secret and internal-endpoint detection
- Input-length enforcement
- Optional semantic analysis through a caller-supplied AI hook
- Optional OpenAI Responses API connector with native schema models
- Optional Rootly incident notification

The core checks run in-process and have no runtime gem dependencies.

## Installation

```ruby
gem "olyx-guardrails", "~> 0.3"
```

```bash
bundle install
```

Ruby 3.4 or newer is required. The repository pins the current Ruby 3.4 patch
release in `.ruby-version` for rbenv users.

## Decision and transformation are separate

Use `check` to make an allow/block decision:

```ruby
require "olyx/guardrails"

result = Olyx::Guardrails.check(
  input,
  block_injections: true,
  block_secrets:    true
)

return forbidden unless result[:allowed]
```

Use `redact` when transformed text is required:

```ruby
redaction = Olyx::Guardrails.redact(input)

safe_input = redaction[:text]
redaction[:redacted]      # true when text changed
redaction[:pii_detected]  # true when regex-detected PII was removed
redaction[:secret_leaked] # true when a secret was removed
```

`check` never claims to transform input, and `redact` never makes an
allow/block decision.

## `Olyx::Guardrails.check`

```ruby
Olyx::Guardrails.check(
  input,
  max_input_length: 10_000,
  block_injections: true,
  block_secrets:    false,
  custom_patterns:  [],
  ai_analyzer:      nil
)
```

| Option | Type | Default | Description |
|---|---|---|---|
| `input` | any | — | Converted via `to_s` |
| `max_input_length` | non-negative Integer | `10_000` | Rejects oversized input before content scans |
| `block_injections` | Boolean | `true` | Makes detected injection attempts disallowed |
| `block_secrets` | Boolean | `false` | Makes detected secrets disallowed |
| `custom_patterns` | Array<String> | `[]` | Additional case-insensitive secret regexes |
| `ai_analyzer` | callable or nil | `nil` | Optional semantic analyzer |

Invalid options raise `ArgumentError`; configuration mistakes do not silently
degrade into an allow decision.

```ruby
{
  allowed:           Boolean,
  pii_detected:      Boolean,
  injection_attempt: Boolean,
  secret_leaked:     Boolean,
  risk_score:        Float,
  checks: [
    { type: "pii",       allowed: true,    detected: Boolean },
    { type: "injection", allowed: Boolean, injection_attempt: Boolean, patterns: Array },
    { type: "secret",    allowed: Boolean, leaked: Boolean, count: Integer },
    { type: "length",    allowed: Boolean, length: Integer, max_length: Integer }
  ],
  ai_analysis: Hash # only when ai_analyzer is supplied and runs
}
```

The length check runs first. When it fails, regex and AI checks are skipped and
content checks carry `skipped: true`.

## `Olyx::Guardrails.redact`

```ruby
Olyx::Guardrails.redact(
  input,
  max_input_length: 10_000,
  custom_patterns:  []
)
```

The returned `:text` has every regex-detected PII and secret match removed.
Repeated credentials in the same category are all redacted. Findings expose a
masked value, a short SHA-256 fingerprint, and source offsets—not plaintext
credentials.

```ruby
{
  text:           String,
  redacted:       Boolean,
  pii_detected:   Boolean,
  secret_leaked:  Boolean,
  findings: [
    {
      category:    String,
      matched:     String,  # masked
      fingerprint: String,  # "sha256:..."
      start:       Integer,
      end:         Integer
    }
  ]
}
```

An oversized input raises `ArgumentError` rather than running an unbounded
transformation.

## AI analyzer hook

The optional hook receives `(text, context)` and returns a Hash or a schema
model implementing `deep_to_h`/`to_h`:

```ruby
hook = lambda do |text, context|
  {
    injection_attempt: false,
    pii_detected:      false,
    secret_leaked:     false,
    risk_score:        0.2,
    reason:            "No semantic policy violation found"
  }
end

result = Olyx::Guardrails.check(input, ai_analyzer: hook)
```

Boolean findings must be actual `true` or `false` values. Invalid responses and
hook exceptions are recorded under `result[:ai_analysis][:error]`; regex
findings remain authoritative. AI findings can add a violation but cannot clear
one.

The hook receives raw input. If it calls a third-party model, the caller is
responsible for data-residency, privacy, and vendor-trust requirements.

### OpenAI structured-output connector

Add the official SDK only in applications that use this connector:

```ruby
gem "openai", "~> 0.62"
```

```ruby
require "openai"
require "olyx/guardrails"
require "olyx/guardrails/integrations/openai_analyzer"

openai = OpenAI::Client.new(api_key: ENV.fetch("OPENAI_API_KEY"))

analyzer = Olyx::Guardrails::Integrations::OpenAIAnalyzer.new(
  client: openai,
  model: ENV.fetch("OPENAI_MODEL"),
  request_options: { timeout: 15, max_retries: 1 }
)

result = Olyx::Guardrails.check(input, ai_analyzer: analyzer)
```

The connector sends the built-in
`OpenAIAnalyzer::AnalysisSchema < OpenAI::BaseModel` through the Responses API
and consumes the SDK's parsed schema-model object. Requests default to
`store: false`; refusals, API failures, and missing parsed output are bounded
under `result[:ai_analysis][:error]` without clearing local findings.

A custom OpenAI schema model can be supplied with `schema:`. It should expose
the analyzer fields shown above; unknown fields are discarded by
`Guardrails.check`.

#### Model compatibility and minimum

The connector has no model allowlist or baked-in default. It forwards String or
Symbol model identifiers unchanged, so aliases, dated snapshots, and fine-tuned
model IDs work when the selected model supports both:

1. text output through `v1/responses`; and
2. Structured Outputs.

That capability check—not a particular model name—is the technical minimum.
The API returns an error under `result[:ai_analysis][:error]` when the selected
model cannot satisfy it. Verify both features on the
[OpenAI model catalog](https://developers.openai.com/api/docs/models) because
model availability and capabilities change independently of this gem.

Do not use models whose catalog entry says **Structured outputs: Not
supported**. This excludes GPT-3.5 Turbo, GPT-4, GPT-4 Turbo, Realtime models,
and specialized image, video, audio, transcription, speech, embedding, and
moderation models. JSON mode is not used as a fallback because valid JSON alone
does not guarantee this connector's schema.

For the broadest model portability, leave `response_options: {}`. Parameters
such as `temperature`, reasoning effort, verbosity, and tool configuration are
model-specific and can make an otherwise compatible model reject the request.
Custom and fine-tuned models remain compatible only when their effective model
supports Structured Outputs; custom schemas must also stay within that model's
supported JSON Schema subset.

Mini and nano text models that support Structured Outputs are technically
compatible; model size is not rejected in code. However, schema conformance
only guarantees the output shape, not correct security classification.
Therefore, do not establish a production minimum from cost, latency, or a
successful schema response alone. Require representative adversarial
evaluations for false negatives, false positives, refusals, latency, and cost.
Keep the local deterministic findings authoritative. OpenAI's
[Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs)
also notes that structured responses can still contain mistakes.

The gem and its optional OpenAI connector require Ruby 3.4 or newer.

## Component APIs

### PII

```ruby
PiiScrubber.scrub(text)
PiiScrubber.scrub_messages(messages)
PiiScrubber.scrub_messages_with_detection(messages)
```

String message content and array-style text content blocks are supported
without changing symbol/string key style.

### Injection detection

```ruby
InjectionDetector.scan(messages)
InjectionDetector.injection?(text)
```

Multi-turn patterns require an adjacent `user` → `assistant` role transition.

### Secret handling

The operation is explicit:

```ruby
SecretScanner.scan(text, custom_patterns: [])   # detect only
SecretScanner.redact(text, custom_patterns: []) # transform
SecretScanner.scan!(text, custom_patterns: [])  # raise Blocked on detection
```

Invalid custom regexes raise `ArgumentError`. Custom regexes are trusted
configuration: review them for pathological backtracking before deployment.

## Risk score

The heuristic score is injection (`0.50`) + secret (`0.25`) + PII (`0.10`) +
any blocked check (`0.15`), clamped to `0.0..1.0`. It supports graduated
responses; it is not a probability or calibrated model confidence.

## Rootly integration

```ruby
require "olyx/guardrails/integrations/rootly_notifier"

notifier = Olyx::Guardrails::Integrations::RootlyNotifier.new(
  api_key:     ENV.fetch("ROOTLY_API_KEY"),
  environment: ENV["RAILS_ENV"]
)

notifier.notify(
  result,
  input:    input,
  metadata: { user_id: current_user.id, endpoint: request.path }
)
```

Input previews, AI reasons, environment names, and metadata are bounded and
redacted before delivery. The notifier performs a synchronous HTTPS request
with a 5-second open timeout and 10-second read timeout; use a background job on
latency-sensitive paths.

## Limitations

- Pattern-based injection detection can miss paraphrasing, translation,
  encoding, homoglyphs, or new attack techniques.
- Secret coverage is format-based and not exhaustive. GCP, Azure, Stripe,
  PEM private keys, and generic high-entropy strings are not currently covered.
- PII patterns remain biased toward common US/Western formats.
- Redaction addresses recognized data patterns; it is not a replacement for
  authorization, output policy enforcement, or a data-loss-prevention system.

## Development and security

```bash
bundle exec rake test
COVERAGE=true bundle exec rake test
gem build olyx-guardrails.gemspec
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development expectations and
[SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

Apache-2.0. See [LICENSE](LICENSE).
