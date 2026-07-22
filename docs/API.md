# Olyx Guardrails API Reference

Decision, transformation, and exception-driven enforcement are intentionally
separate operations.

Complete integration examples are available for
[framework-free Ruby](../examples/ruby_only.rb) and
[opt-in Rails boundaries](../examples/rails_opt_in.rb).

## Rails adapter

Require `olyx/guardrails` normally in a Rails application. The Railtie loads
automatically after Rails and finalizes configuration after application
initializers:

```ruby
Olyx::Guardrails::Rails.configure do |config|
  config.enabled = true
  config.policy_path = Rails.root.join("config/olyx_guardrails.yml")
  config.ai_analyzer = nil
  config.notifier_handlers = {}
  config.filter_parameters = %i[prompt system_prompt ai_input llm_input]
end
```

Set either `policy` to a `Policy` instance or `policy_path` to direct or
environment-keyed YAML, never both. Configuration becomes immutable after
application boot. Calling the Rails facade while `enabled` is false raises
`ConfigurationError` rather than silently allowing input.

`Olyx::Guardrails::Rails.check(input, metadata: {})` delegates to the core
check with the configured policy and analyzer, emits sanitized Active Support
events, and invokes configured notifier handlers for non-zero-risk results.
`Olyx::Guardrails::Rails.redact(input)` delegates to the core transformation.
The Rails facade also exposes `check_messages(messages, metadata: {})`,
`check_output(output, metadata: {})`, and `redact_output(output)`.

Including `Olyx::Guardrails::Rails::Controller` adds private
`guardrails_check`, `guardrails_check!`, and `guardrails_redact` helpers.
`guardrails_check!` raises `Olyx::Guardrails::Blocked` when input is rejected.
Its `decision` contains only `policy_name`, `allowed`, `risk_score`,
`violations`, and `policy_rules`.

`Olyx::Guardrails::Rails::ActiveJobHandler.new(job:, queue: nil)` accepts an
Active Job class or reload-safe String/Symbol constant name. Its `call(event)`
method enqueues the sanitized notification event with `perform_later`.

Other Rails entry points are opt-in and use the same finalized policy,
instrumentation, notification, and `Blocked` decision contract:

- Include `Rails::GraphQL` and call `guardrails_check_graphql!` or
  `guardrails_check_graphql_output!` from resolvers and mutations.
- Include `Rails::ActionCable` and call `guardrails_check_cable!` or
  `guardrails_check_cable_output!` from channel methods.
- Include `Rails::Job` in an Active Job class and declare positional indexes or
  keyword names with `guardrails_input_arguments 0, :system_prompt`.
- Add `validates :prompt, olyx_guardrails: true` to Active Model objects. Pass a
  `policy:` option to use a specific core policy without the Rails facade.
- Use `Rails::Upload.check` or `check!` with `extractor:`. The callable owns file
  parsing and must return a String.
- Use `Rails::Enforcer.check!`, `check_messages!`, or `check_output!` in service
  objects, callbacks, and custom ingestion paths.

**No adapter auto-discovers AI-bound data. File parsing, streaming token,**
**interception, and callback placement remain application responsibilities.**

## `Olyx::Guardrails::Policy`

```ruby
policy = Olyx::Guardrails::Policy.new(
  name:             "production",
  max_input_length: 10_000,
  block_pii:        false,
  block_injections: true,
  block_secrets:    false,
  ai_failure_mode:  :block,
  secret_patterns:  ["company-token-[a-z0-9]{24}"],
  rules: [
    {
      name:        :restricted_project,
      description: "Internal project identifiers",
      terms:       ["Project Falcon"],
      patterns:    [/PF-\d{4}/],
      match:       :whole_word,
      block:       true,
      replacement: "[RESTRICTED_PROJECT]"
    }
  ]
)
```

Policies and their rules are immutable. `rules` accepts `PolicyRule` instances
or Hashes. Rule names must be unique identifiers. Patterns must be a non-empty
Array of Strings or Regexps and must not match empty text. Strings are compiled
case-insensitively; Regexps retain their options. Matching has a per-pattern
timeout.

`match:` applies to `terms`: `:substring` is the default, `:whole_word` adds
alphanumeric boundaries, and `:regexp` treats term strings as regex source.
Values under `patterns` are always regexes. `ai_failure_mode:` accepts `:allow`
(preserve the deterministic result), `:block` (add a failed AI check), or
`:raise` (`AiAnalyzerError`).

`block: true` rejects matching input during `check`; `block: false` only flags
it. Both are transformed by `redact`. `replacement` defaults to
`[RESTRICTED:RULE_NAME]`.

Use `Policy.from_h(configuration)` for a String- or Symbol-keyed Hash loaded
from YAML or JSON. Invalid configuration raises `ArgumentError` during policy
construction. `Policy.default` is a reused immutable policy with a 10,000
character limit, injection blocking enabled, PII/secret blocking disabled, and
empty `secret_patterns` and `rules`.
`secret_patterns` extends credential detection while keeping those findings in
the `secret` category; `rules` creates distinct business-policy findings.

## `Olyx::Guardrails.check`

```ruby
Olyx::Guardrails.check(
  input,
  policy:      Olyx::Guardrails::Policy.default,
  ai_analyzer: nil
)
```

Returns:

```ruby
{
  allowed:           Boolean,
  pii_detected:      Boolean,
  injection_attempt: Boolean,
  secret_leaked:     Boolean,
  policy_name:       String,
  policy_violated:   Boolean,
  policy_findings:   Array<Hash>,
  risk_score:        Float,
  checks:            Array<Hash>,
  ai_analysis:       Hash # only when the hook runs
}
```

`check` never transforms input. `policy` must be a `Policy`; `ai_analyzer` must
be callable or nil.

The five check entries are:

- `pii`: `type`, `allowed`, `detected`
- `injection`: `type`, `allowed`, `injection_attempt`, `patterns`
- `secret`: `type`, `allowed`, `leaked`, `count`
- `policy`: `type`, `allowed`, `violated`, `count`, `findings`
- `length`: `type`, `allowed`, `length`, `max_length`

When length fails, the first four entries contain `skipped: true`.
When `ai_failure_mode: :block` handles an analyzer error, `checks` also contains
`{type: "ai", allowed: false, error: true}`.

Policy finding shape:

```ruby
{
  rule:        String,
  description: String,  # omitted when the rule has no description
  blocked:     Boolean,
  matched:     String,  # always "[REDACTED]", never plaintext
  fingerprint: String,  # short SHA-256 correlation fingerprint
  start:       Integer,
  end:         Integer
}
```

## `Olyx::Guardrails.redact`

```ruby
Olyx::Guardrails.redact(
  input,
  policy: Olyx::Guardrails::Policy.default
)
```

Returns:

```ruby
{
  text:           String,
  redacted:       Boolean,
  pii_detected:   Boolean,
  secret_leaked:  Boolean,
  policy_name:     String,
  policy_violated: Boolean,
  policy_findings: Array<Hash>,
  findings:       Array<Hash>
}
```

The method removes every regex-detected PII, secret, and restricted-policy
match. `findings` contains secret findings; `policy_findings` remains distinct.
It raises `ArgumentError` for a non-Policy value or oversized input.

## Structured messages and completed output

```ruby
Olyx::Guardrails.check_messages(messages, policy: policy, ai_analyzer: nil)
Olyx::Guardrails.check_output(output, policy: policy, ai_analyzer: nil)
Olyx::Guardrails.redact_output(output, policy: policy)
```

`check_messages` accepts an Array of message Hashes, evaluates their combined
text with the normal pipeline, and adds adjacent `user` → `assistant`
multi-turn injection detection. String content and array-style text blocks are
supported. `check_output` and `redact_output` are explicit aliases for checking
or transforming a completed output value; they do not provide streaming-token
enforcement.

## AI analyzer contract

A hook receives:

```ruby
[
  text,
  {
    pii_detected:       Boolean,
    injection_attempt:  Boolean,
    injection_patterns: Array<Hash>,
    secret_leaked:      Boolean,
    policy_violated:    Boolean,
    policy_rules:       Array<String>
  }
]
```

It may return a Hash or a schema-model object implementing `deep_to_h`/`to_h`.
String and Symbol keys are accepted. The normalized shape is:

```ruby
{
  injection_attempt: Boolean,
  pii_detected:      Boolean,
  secret_leaked:     Boolean,
  risk_score:        Numeric,
  reason:            String
}
```

Finding fields must be real Boolean values. Non-finite scores are ignored.
Exceptions and malformed responses are returned as a bounded `:error` under
`:ai_analysis`, then handled according to the policy's `ai_failure_mode`.

## `Integrations::OpenAIAnalyzer`

Load the optional connector explicitly:

```ruby
require "openai"
require "olyx/guardrails/integrations/openai_analyzer"

analyzer = Olyx::Guardrails::Integrations::OpenAIAnalyzer.new(
  client: OpenAI::Client.new,
  model: ENV.fetch("OPENAI_MODEL"),
  schema: nil,             # defaults to the built-in OpenAI::BaseModel schema
  store: false,
  request_options: nil,
  response_options: {}
)

Olyx::Guardrails.check(input, ai_analyzer: analyzer)
```

The connector calls `client.responses.create` with `text:` set to an OpenAI
schema model, then returns the parsed model from the response's output content.
The built-in schema requires all five analyzer fields. Pass another
`OpenAI::BaseModel` subclass through `schema:` to customize field descriptions
or composition while retaining the analyzer contract.

`response_options` accepts additional Responses API parameters, but cannot
replace `model`, `input`, `text`, `store`, or `request_options`. A refusal or
response without parsed structured output raises internally and is recorded by
`Guardrails.check` under `:ai_analysis[:error]`. The connector is non-streaming.

The `openai` gem is optional and is loaded lazily. Constructing a connector
without an injected client/schema gives a clear `LoadError` when the SDK is not
installed.

### OpenAI model contract

`model:` accepts a non-empty String or Symbol and is forwarded unchanged.
There is intentionally no static model allowlist: aliases, snapshots,
fine-tuned IDs, and future text models can be used without a library release.

The selected model must provide text output on `v1/responses` and support
Structured Outputs. Models that only support Chat Completions, JSON mode, or a
specialized endpoint are not compatible. In particular, do not configure
GPT-3.5 Turbo, GPT-4, GPT-4 Turbo, Realtime, image/video generation,
audio/transcription/speech, embedding, or moderation models as the minimum for
this connector.

Check the current [OpenAI model
catalog](https://developers.openai.com/api/docs/models) before deployment;
capabilities and availability are intentionally not frozen into this library.

Leave `response_options` empty for the most portable configuration.
Temperature, reasoning, verbosity, and tool parameters are not uniform across
model families. A custom or fine-tuned identifier is compatible only when its
effective model supports Structured Outputs, and custom schemas must stay
within that model's supported JSON Schema subset.

Mini and nano models are accepted when they meet the API capability contract.
Structured Outputs guarantees schema conformance, not that the model classified
adversarial input correctly. Establish the production minimum with versioned
evaluation thresholds—including false-negative, false-positive, refusal,
latency, and cost targets—not merely model size or a successful request.
OpenAI documents that [Structured Outputs can still contain semantic
mistakes](https://developers.openai.com/api/docs/guides/structured-outputs#handling-mistakes).

## `PiiScrubber`

```ruby
PiiScrubber.scrub(text)
PiiScrubber.scrub_messages(messages)
PiiScrubber.scrub_messages_with_detection(messages)
```

Recognized formats include email, formatted/international phone, structurally
valid U.S. SSN, Luhn-valid Canadian SIN, Luhn-valid payment card, valid IPv4
and IPv6, token prefixes, contextualized passports, formatted/checksum-valid
IBAN, and calendar-valid contextualized dates of birth.

Message helpers accept an Array of Hashes and support String content or
array-style text blocks. They preserve symbol/string key style.

## `InjectionDetector`

```ruby
InjectionDetector.scan(messages)
InjectionDetector.check(messages)
InjectionDetector.injection?(text)
```

`scan` and `check` return:

```ruby
{
  injection_attempt: Boolean,
  patterns: [
    { role: String, match: String }
  ]
}
```

Multi-turn matching considers only adjacent `user` → `assistant` messages.
Malformed message arrays raise `ArgumentError`.

Single-message and adjacent-turn matching inspect bounded variants produced by
NFKC normalization, common Greek/Cyrillic homoglyph folding, zero-width removal,
and one decoding layer for URL, HTML-entity, Unicode-escape, and Base64
encoding.

## `SecretScanner`

### Detect

```ruby
SecretScanner.scan(text, custom_patterns: [])
# => { leaked: Boolean, findings: Array<Hash> }
```

### Redact

```ruby
SecretScanner.redact(text, custom_patterns: [])
# => { text: String, leaked: Boolean, findings: Array<Hash> }
```

Every non-overlapping occurrence is redacted. A confidentiality marker causes
the whole input to be redacted because the marker alone does not identify the
sensitive span.

### Enforce with an exception

```ruby
SecretScanner.scan!(text, custom_patterns: [])
```

Raises `SecretScanner::Blocked` when any finding exists. `#findings` contains
the same safe shape exposed by `scan`.

### Finding shape

```ruby
{
  category:    String,
  matched:     String,  # masked, never plaintext
  fingerprint: String,  # short SHA-256 correlation fingerprint
  start:       Integer,
  end:         Integer
}
```

Built-in categories include common cloud/SaaS keys, JWTs, PEM private keys,
credential-bearing database URLs, confidentiality markers, and private network
endpoints. Custom patterns must be an Array of valid non-empty-matching regex
Strings and are compiled case-insensitively. Invalid values raise
`ArgumentError`.
They extend secret-format detection and are therefore classified as secrets.
Use a `PolicyRule` for named business restrictions.

## `Olyx::Guardrails::Notifier`

```ruby
notifier = Olyx::Guardrails::Notifier.new(
  policy: policy,
  handlers: {
    logger: ->(event) { logger.warn(event) },
    queue: ->(event) { NotificationJob.perform_later(event) }
  }
)

notifier.notify(result, input: input, metadata: { request_id: request_id })
```

`policy:` is required and should be the same immutable `Policy` used to produce
`result`. `handlers:` is a non-empty Hash of up to 20 unique String or Symbol
names mapped to objects responding to `call(event)`.

Returns `nil` for a zero-risk result. Otherwise it returns:

```ruby
{
  success: Boolean,
  event: Hash,       # deeply frozen event delivered to every handler
  deliveries: [
    { handler: String, success: Boolean, error: String } # error only on failure
  ]
}
```

The versioned event contract is vendor-neutral:

```ruby
{
  schema_version:    1,
  event:             "guardrail.violation",
  policy_name:       String,
  allowed:           Boolean,
  risk_score:        Float,
  violations:        Array<String>,
  policy_rule_count: Integer,
  ai_reason:         String,       # optional
  input_preview:     String,       # optional, max 300 characters plus ellipsis
  metadata:          Hash<String, String> # maximum 20 entries
}
```

All handlers run synchronously and independently. One exception does not stop
later handlers; errors are returned per handler. Event text, metadata keys and
values, and handler error messages are bounded and policy-redacted. Use a queue
handler for asynchronous delivery to email, webhooks, chat, incident systems,
or other external services. `notify` does not raise for event construction or
handler failures; invalid constructor configuration raises `ArgumentError`.
