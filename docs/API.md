# Olyx Guardrails API Reference

This reference defines the public Ruby contracts for Olyx Guardrails 1.1.
Task-oriented documentation is available in the
[documentation index](README.md).

## Conventions

- Public operations accept keyword arguments exactly as shown.
- Inputs documented as `#to_s` are converted with `to_s`.
- Invalid configuration raises before evaluation.
- Hash contracts use Symbol keys unless a section explicitly says otherwise.
- `start` offsets are inclusive, and `end` offsets are exclusive.
- Decisions and transformations are separate operations.

Load the framework-free API with:

```ruby
require "olyx/guardrails"
```

Load the Rails adapter explicitly when Rails is already available:

```ruby
require "olyx/guardrails/rails"
```

The Railtie loads automatically when `Rails::Railtie` is defined during the
normal `require "olyx/guardrails"` path.

## `Olyx::Guardrails`

### `.check`

```ruby
Olyx::Guardrails.check(
  input,
  policy: Olyx::Guardrails::Policy.default,
  llm_provider: nil
)
```

Runs the length check, deterministic content checks, optional semantic
analysis, result merging, and risk scoring.

Arguments:

| Argument | Contract |
|---|---|
| `input` | Any object; converted with `to_s` |
| `policy` | `Olyx::Guardrails::Policy` |
| `llm_provider` | Object responding to `call(text, context)`, or `nil` |

Returns a [decision result](#decision-result).

Raises:

- `ArgumentError` when `policy` is not a `Policy`;
- `ArgumentError` when `llm_provider` is not callable or `nil`; and
- `Olyx::Guardrails::LlmProviderError` when provider evaluation fails and the
  policy uses `llm_failure_mode: :raise`.

An oversized input returns a rejected decision. It does not raise.

### `.check_messages`

```ruby
Olyx::Guardrails.check_messages(
  messages,
  policy: Olyx::Guardrails::Policy.default,
  llm_provider: nil
)
```

`messages` must be an Array of Hashes. Each Hash may use String or Symbol keys:

```ruby
[
  { role: "user", content: "First turn" },
  { "role" => "assistant", "content" => "Second turn" }
]
```

Supported `content` values are:

- a String; or
- an Array of Hash blocks containing a String under `text`.

Other content values contribute an empty string. Roles normalize with
`to_s.downcase`.

The method joins extracted message text with newlines for single-input checks
and the optional LLM provider. Injection detection also evaluates adjacent
`user` to `assistant` transitions.

Returns a [decision result](#decision-result).

Raises `ArgumentError` when `messages` is not an Array of Hashes, or when the
policy/provider arguments are invalid.

### `.check_output`

```ruby
Olyx::Guardrails.check_output(
  output,
  policy: Olyx::Guardrails::Policy.default,
  llm_provider: nil
)
```

An explicit alias for `.check`. The separate name lets applications identify a
completed-output boundary in code and telemetry. It does not inspect streaming
tokens.

### `.redact`

```ruby
Olyx::Guardrails.redact(
  input,
  policy: Olyx::Guardrails::Policy.default
)
```

Transforms recognized PII, secrets, and restricted-policy matches. Returns a
[redaction result](#redaction-result).

Raises:

- `ArgumentError` when `policy` is not a `Policy`; and
- `ArgumentError` when converted input length exceeds
  `policy.max_input_length`.

This method does not make an allow/block decision.

### `.redact_output`

```ruby
Olyx::Guardrails.redact_output(
  output,
  policy: Olyx::Guardrails::Policy.default
)
```

An explicit alias for `.redact` at a completed-output boundary.

## Decision result

Core decision methods return:

```ruby
{
  allowed: Boolean,
  pii_detected: Boolean,
  injection_attempt: Boolean,
  secret_leaked: Boolean,
  policy_name: String,
  policy_violated: Boolean,
  policy_findings: Array<Hash>,
  risk_score: Float,
  checks: Array<Hash>,
  llm_analysis: Hash
}
```

`llm_analysis` is present only when an LLM provider runs. The provider is
skipped when the length check rejects the input.

`checks` is ordered:

1. `pii`;
2. `injection`;
3. `secret`;
4. `policy`;
5. `length`; and
6. `llm`, only for a provider failure handled in block mode.

### PII check

```ruby
{
  type: "pii",
  allowed: Boolean,
  detected: Boolean
}
```

### Injection check

```ruby
{
  type: "injection",
  allowed: Boolean,
  injection_attempt: Boolean,
  patterns: [
    {
      role: String,
      match: String
    }
  ]
}
```

### Secret check

```ruby
{
  type: "secret",
  allowed: Boolean,
  leaked: Boolean,
  count: Integer
}
```

### Policy check

```ruby
{
  type: "policy",
  allowed: Boolean,
  violated: Boolean,
  count: Integer,
  findings: Array<Hash>
}
```

### Length check

```ruby
{
  type: "length",
  allowed: Boolean,
  length: Integer,
  max_length: Integer
}
```

When length rejects the input, the first four checks contain `skipped: true`,
safe false detection fields, and `allowed: true`. The length check remains the
rejected check.

### LLM failure check

When `llm_failure_mode` is `:block`:

```ruby
{
  type: "llm",
  allowed: false,
  error: true
}
```

When an LLM finding adds a deterministic category, the corresponding check also
contains `llm_flagged: true`.

### Policy finding

```ruby
{
  rule: String,
  description: String,
  blocked: Boolean,
  matched: "[REDACTED]",
  fingerprint: "sha256:...",
  start: Integer,
  end: Integer
}
```

`description` is absent when the rule has none. `fingerprint` contains the
first 12 hexadecimal characters of the SHA-256 digest.

## Redaction result

`.redact` and `.redact_output` return:

```ruby
{
  text: String,
  redacted: Boolean,
  pii_detected: Boolean,
  secret_leaked: Boolean,
  policy_name: String,
  policy_violated: Boolean,
  policy_findings: Array<Hash>,
  findings: Array<Hash>
}
```

`redacted` is true when `text` differs from the converted input.
`policy_findings` uses the [policy finding](#policy-finding) contract.
`findings` contains safe secret findings.

A confidentiality marker causes `text` to become `[REDACTED]` because the
marker does not identify one safe span.

## `Olyx::Guardrails::Policy`

### `.default`

```ruby
Olyx::Guardrails::Policy.default
```

Returns one reused, frozen default policy.

### `.from_h`

```ruby
Olyx::Guardrails::Policy.from_h(configuration)
```

Accepts a Hash with top-level String or Symbol keys and delegates to `.new`.
Raises `ArgumentError` for non-Hash input, non-convertible keys, unknown
options, or invalid values.

### `.new`

```ruby
Olyx::Guardrails::Policy.new(
  name: "default",
  max_input_length: 10_000,
  block_pii: false,
  block_injections: true,
  block_secrets: false,
  llm_failure_mode: :allow,
  secret_patterns: [],
  rules: []
)
```

See the [Policies guide](POLICIES.md#policy-options) for each option contract.

Readers:

```ruby
policy.name
policy.max_input_length
policy.llm_failure_mode
policy.secret_patterns
policy.rules
policy.block_pii?
policy.block_injections?
policy.block_secrets?
```

The policy and returned collections are immutable.

## `Olyx::Guardrails::PolicyRule`

```ruby
Olyx::Guardrails::PolicyRule.new(
  name:,
  patterns: [],
  terms: [],
  match: :substring,
  block: true,
  description: nil,
  replacement: nil
)
```

At least one term or pattern is required. See the
[Policies guide](POLICIES.md#policy-rule-options) for validation and matching
semantics.

Readers:

```ruby
rule.name
rule.description
rule.match
rule.patterns
rule.replacement
rule.block?
```

`patterns` returns the compiled regular expressions, including expressions
compiled from `terms`.

## LLM provider contract

`llm_provider` responds to:

```ruby
provider.call(text, context)
```

`text` is the raw converted input. `context` is:

```ruby
{
  pii_detected: Boolean,
  injection_attempt: Boolean,
  injection_patterns: Array<Hash>,
  secret_leaked: Boolean,
  policy_violated: Boolean,
  policy_rules: Array<String>
}
```

The provider returns a Hash or an object implementing `deep_to_h` or `to_h`.
String and Symbol result keys are accepted.

Supported fields are:

```ruby
{
  injection_attempt: Boolean,
  pii_detected: Boolean,
  secret_leaked: Boolean,
  risk_score: Numeric,
  reason: String
}
```

All fields are optional. Unknown fields are discarded.

Boolean fields require literal `true` or `false`. A malformed return value,
invalid Boolean, or raised `StandardError` becomes:

```ruby
{
  error: String
}
```

Errors are bounded to 201 characters. Reasons are converted with `to_s` and
bounded to 500 characters. A finite Numeric score is clamped to `0.0..1.0` and
compared with the deterministic score. Numeric strings and other non-Numeric
values are ignored.

Provider findings are additive:

- `true` can add a PII, injection, or secret finding;
- `false` cannot remove a deterministic finding; and
- the configured policy still decides whether the category blocks.

Provider transport, model selection, authentication, prompting, retries,
timeouts, and response extraction are outside the gem contract.

## `Olyx::Guardrails::PiiScrubber`

### `.scrub`

```ruby
Olyx::Guardrails::PiiScrubber.scrub(text)
```

Returns a redacted String when `text` is a String. Returns non-String input
unchanged.

Built-in replacements include:

| Category | Replacement |
|---|---|
| Email | `[EMAIL]` |
| U.S. Social Security number | `[SSN]` |
| Canadian Social Insurance Number | `[SIN]` |
| Passport | `[PASSPORT]` |
| IBAN | `[IBAN]` |
| Contextual date of birth | `[DOB]` |
| IPv4 or IPv6 address | `[IP]` |
| Token-like PII | `[TOKEN]` |
| Luhn-valid payment card | `[CARD]` |
| Formatted phone number | `[PHONE]` |

Structural and checksum validators reduce false positives for SSNs, SINs,
cards, IP addresses, IBANs, and dates.

### `.scrub_messages`

```ruby
Olyx::Guardrails::PiiScrubber.scrub_messages(messages)
```

Returns an Array with supported message content redacted. Messages and blocks
without a supported String content value remain unchanged. String/Symbol key
style is preserved.

Raises `ArgumentError` unless `messages` is an Array of Hashes.

### `.scrub_messages_with_detection`

```ruby
Olyx::Guardrails::PiiScrubber.scrub_messages_with_detection(messages)
```

Returns:

```ruby
{
  messages: Array<Hash>,
  detected: Boolean
}
```

## `Olyx::Guardrails::InjectionDetector`

### `.scan`

```ruby
Olyx::Guardrails::InjectionDetector.scan(messages)
```

Returns:

```ruby
{
  injection_attempt: Boolean,
  patterns: [
    {
      role: String,
      match: String
    }
  ]
}
```

`messages` must be an Array of Hashes. Detection considers individual messages
and adjacent `user` to `assistant` transitions. Duplicate `match` values are
removed.

### `.check`

```ruby
Olyx::Guardrails::InjectionDetector.check(messages)
```

An alias-by-delegation for `.scan`.

### `.injection?`

```ruby
Olyx::Guardrails::InjectionDetector.injection?(text)
```

Converts `text` with `to_s`, treats it as one user message, and returns a
Boolean.

## `Olyx::Guardrails::SecretScanner`

### `.scan`

```ruby
Olyx::Guardrails::SecretScanner.scan(
  text,
  custom_patterns: []
)
```

Returns:

```ruby
{
  leaked: Boolean,
  findings: Array<Hash>
}
```

### `.redact`

```ruby
Olyx::Guardrails::SecretScanner.redact(
  text,
  custom_patterns: []
)
```

Returns:

```ruby
{
  text: String,
  leaked: Boolean,
  findings: Array<Hash>
}
```

Every non-overlapping secret span is replaced. A confidentiality marker
redacts the complete input.

### `.scan!`

```ruby
Olyx::Guardrails::SecretScanner.scan!(
  text,
  custom_patterns: []
)
```

Returns the `.scan` result when no finding exists. Raises
`Olyx::Guardrails::SecretScanner::Blocked` otherwise.

The exception is a subclass of `Olyx::Guardrails::Blocked`. It exposes:

```ruby
error.findings
error.decision
```

The low-level decision is:

```ruby
{
  policy_name: nil,
  allowed: false,
  risk_score: nil,
  violations: ["secret_leaked"],
  policy_rules: []
}
```

### Custom patterns

`custom_patterns` must be an Array of regular-expression source Strings.
Patterns compile case-insensitively, must be valid, and must not match empty
text.

### Secret finding

```ruby
{
  category: String,
  matched: String,
  fingerprint: "sha256:...",
  start: Integer,
  end: Integer
}
```

`matched` is `[REDACTED]` for values shorter than 12 characters. Longer values
retain the first and last four characters separated by an ellipsis.

Built-in categories include:

- `private_network_address`;
- `internal_endpoint`;
- `aws_access_key`;
- `aws_secret_key`;
- `secret_token`;
- `jwt`;
- `private_key`;
- `database_url`;
- `stripe_key`;
- `google_key`;
- `azure_storage_key`;
- `confidentiality_marker`; and
- `custom_pattern`.

## `Olyx::Guardrails::Notifier`

### `.new`

```ruby
Olyx::Guardrails::Notifier.new(
  policy:,
  handlers:
)
```

`policy` must be a `Policy`. `handlers` must be a non-empty Hash with at most
20 entries.

Handler names:

- are Strings or Symbols;
- contain letters, numbers, underscores, periods, colons, or hyphens;
- begin with a letter;
- contain at most 100 characters; and
- remain unique after conversion to String.

Each handler responds to `call(event)`.

### `#notify`

```ruby
notifier.notify(
  result,
  input: nil,
  metadata: {}
)
```

`result` must be a Hash containing a finite Numeric `risk_score` from `0.0`
through `1.0`. `metadata` must be a Hash. Invalid arguments raise
`ArgumentError`.

Returns `nil` only when a valid result has a zero `risk_score`.

A positive score returns a frozen delivery summary:

```ruby
{
  success: Boolean,
  event: Hash,
  deliveries: [
    {
      handler: String,
      success: Boolean,
      error: String
    }
  ]
}
```

`error` is present only for a failed handler. Every handler receives the same
deeply frozen event. Handlers run synchronously and independently.

Event-building failures return:

```ruby
{
  success: false,
  error: String,
  deliveries: []
}
```

See the [notification event contract](OPERATIONS.md#notification-event).

## Exceptions

### `Olyx::Guardrails::ConfigurationError`

Raised when Rails integration cannot establish or use valid configuration.

### `Olyx::Guardrails::LlmProviderError`

Raised when provider evaluation fails and the active policy uses
`llm_failure_mode: :raise`.

### `Olyx::Guardrails::Blocked`

Raised by explicit enforcement entry points:

```ruby
error.decision
```

The default message is `content blocked by guardrail policy`; it is neutral
across input, message, and completed-output boundaries.

`decision` is a content-free Hash with:

```ruby
{
  policy_name: String | nil,
  allowed: false,
  risk_score: Float | nil,
  violations: Array<String>,
  policy_rules: Array<String>
}
```

The low-level secret exception uses `nil` for `policy_name` and `risk_score`
because `SecretScanner.scan!` does not run a policy decision. The Hash and
nested collections are frozen.

### `Olyx::Guardrails::SecretScanner::Blocked`

A `Blocked` subclass raised by `SecretScanner.scan!`. It additionally exposes
safe secret `findings`.

## Rails API

The Rails facade and adapter signatures are defined in the
[Rails integration guide](RAILS.md). Core result contracts remain identical.

Public Rails entry points are:

```ruby
Olyx::Guardrails::Rails.configure(**options)
Olyx::Guardrails::Rails.configuration
Olyx::Guardrails::Rails.finalize!(environment:)
Olyx::Guardrails::Rails.check(input, metadata: {})
Olyx::Guardrails::Rails.check_messages(messages, metadata: {})
Olyx::Guardrails::Rails.check_output(output, metadata: {})
Olyx::Guardrails::Rails.redact(input)
Olyx::Guardrails::Rails.redact_output(output)

Olyx::Guardrails::Rails::Enforcer.check!(input, metadata: {})
Olyx::Guardrails::Rails::Enforcer.check_messages!(messages, metadata: {})
Olyx::Guardrails::Rails::Enforcer.check_output!(output, metadata: {})

Olyx::Guardrails::Rails::Upload.check(upload, extractor:, metadata: {})
Olyx::Guardrails::Rails::Upload.check!(upload, extractor:, metadata: {})

Olyx::Guardrails::Rails::ActiveJobHandler.new(job:, queue: nil)
```

Every Rails `metadata:` argument must be a Hash. Invalid metadata consistently
raises `ArgumentError` before evaluation or notification delivery.

Controller, GraphQL, Action Cable, Active Job, and Active Model integration
methods are documented in their corresponding
[Rails guide sections](RAILS.md#controller-boundaries).
