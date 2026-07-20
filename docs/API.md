# Olyx Guardrails API Reference

This reference describes the breaking 0.3 API. Decision, transformation, and
exception-driven enforcement are intentionally separate operations.

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

Returns:

```ruby
{
  allowed:           Boolean,
  pii_detected:      Boolean,
  injection_attempt: Boolean,
  secret_leaked:     Boolean,
  risk_score:        Float,
  checks:            Array<Hash>,
  ai_analysis:       Hash # only when the hook runs
}
```

`check` never transforms input. `block_injections` and `block_secrets` must be
Booleans. `max_input_length` must be a non-negative Integer. Invalid
configuration raises `ArgumentError`.

The four check entries are:

- `pii`: `type`, `allowed`, `detected`
- `injection`: `type`, `allowed`, `injection_attempt`, `patterns`
- `secret`: `type`, `allowed`, `leaked`, `count`
- `length`: `type`, `allowed`, `length`, `max_length`

When length fails, the first three entries contain `skipped: true`.

## `Olyx::Guardrails.redact`

```ruby
Olyx::Guardrails.redact(
  input,
  max_input_length: 10_000,
  custom_patterns:  []
)
```

Returns:

```ruby
{
  text:           String,
  redacted:       Boolean,
  pii_detected:   Boolean,
  secret_leaked:  Boolean,
  findings:       Array<Hash>
}
```

The method removes every regex-detected PII and secret match. It raises
`ArgumentError` for invalid options, invalid custom regexes, or oversized input.

## AI analyzer contract

A hook receives:

```ruby
[
  text,
  {
    pii_detected:       Boolean,
    injection_attempt:  Boolean,
    injection_patterns: Array<Hash>,
    secret_leaked:      Boolean
  }
]
```

It may return:

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
`:ai_analysis`.

## `PiiScrubber`

```ruby
PiiScrubber.scrub(text)
PiiScrubber.scrub_messages(messages)
PiiScrubber.scrub_messages_with_detection(messages)
```

Recognized formats include email, formatted/international phone, structurally
valid U.S. SSN, Luhn-valid payment card, valid IPv4, token prefixes,
contextualized passports, checksum-valid IBAN, and contextualized dates of
birth.

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

Custom patterns must be an Array of valid regex Strings and are compiled
case-insensitively. Invalid values raise `ArgumentError`.

## `RootlyNotifier`

Load explicitly:

```ruby
require "olyx/guardrails/integrations/rootly_notifier"
```

```ruby
notifier = Olyx::Guardrails::Integrations::RootlyNotifier.new(
  api_key:     ENV.fetch("ROOTLY_API_KEY"),
  environment: "production"
)

notifier.notify(result, input: input, metadata: { request_id: request_id })
```

Returns a success/error Hash, or `nil` for a zero-risk result. Input, AI reason,
environment, and metadata are bounded and redacted before the request is sent.
The notifier never raises during payload construction or delivery.
