# Olyx Guardrails API Reference

This document describes the public API and internal behavior for `olyx-guardrails`.

## Module: `Olyx::Guardrails`

### `Olyx::Guardrails.check(input, max_input_length: 10_000, injection_block: true, secret_action: "alert", custom_patterns: [])`

Runs the full suite of guardrails on a single input string.

#### Parameters

- `input` - any object; converted to string via `to_s`.
- `max_input_length` - maximum allowed length before the `length` check fails.
- `injection_block` - when `true`, injection attempts cause `allowed: false`.
- `secret_action` - one of:
  - `"alert"`
  - `"redact"`
  - `"block"`
- `custom_patterns` - custom regular expression strings for secret detection.

#### Return value

A hash containing:

- `:allowed` - overall boolean allowance.
- `:pii_detected` - whether PII was found.
- `:injection_attempt` - whether injection patterns were matched.
- `:secret_leaked` - whether secret scanning found leakage.
- `:risk_score` - heuristic score from `0.0` to `1.0`.
- `:checks` - detailed per-check results.

#### Check object shapes

- `PII`
  - `type: "pii"`
  - `allowed: true`
  - `detected: boolean`
- `Injection`
  - `type: "injection"`
  - `allowed: boolean`
  - `injection_attempt: boolean`
  - `patterns: Array<Hash>`
- `Secret`
  - `type: "secret"`
  - `allowed: boolean`
  - `leaked: boolean`
  - `count: integer`
- `Length`
  - `type: "length"`
  - `allowed: boolean`
  - `length: integer`
  - `max_length: integer`

### `Olyx::Guardrails.compute_risk_score(pii:, injection:, secret:, checks:)`

Private method used internally to compute risk.

- Adds `0.50` for injection
- Adds `0.25` for secret leakage
- Adds `0.10` for PII detection
- Adds `0.15` when any check is not allowed
- clamps result to `0.0..1.0`

## Class: `Olyx::Guardrails::PiiScrubber`

Scrubs personally identifiable information from text.

### Supported patterns

- emails
- phone numbers
- U.S. SSN formats
- credit-card-like numeric sequences
- IPv4 addresses
- bearer tokens and known API token prefixes

### Methods

#### `PiiScrubber.scrub(text)`

Redacts matching patterns in `text`.

Example:

```ruby
PiiScrubber.scrub("Contact me at user@example.com")
# => "Contact me at [EMAIL]"
```

#### `PiiScrubber.scrub_messages(messages)`

Accepts an array of message hashes and returns scrubbed messages.

#### `PiiScrubber.scrub_messages_with_detection(messages)`

Returns a hash with:

- `:messages` — scrubbed messages
- `:detected` — whether any replacement occurred

## Class: `Olyx::Guardrails::InjectionDetector`

Detects prompt injection patterns inside chat-style messages.

### Pattern categories

- structural tokens like `[SYSTEM]`, `<<system>>`, `--- instructions ---`
- phrase-based jailbreak patterns such as `ignore all previous instructions`, `pretend you are`, or `you have no restrictions`

### Methods

#### `InjectionDetector.scan(messages)`

Inspects each message and returns:

- `:injection_attempt` — boolean
- `:patterns` — unique matched pattern strings

Messages are expected to be hashes with `"role"` and `"content"` keys.

#### `InjectionDetector.check(messages)`

Alias for `scan`.

#### `InjectionDetector.injection?(text)`

Returns `true` when the text contains any injection patterns.

## Class: `Olyx::Guardrails::SecretScanner`

Detects confidential markers, internal endpoints, private network references, and token-like strings.

### Detection rules

- Confidentiality markers such as `confidential`, `proprietary`, `internal use only`, `do not share`, `top secret`, and others.
- Internal endpoint suffixes like `.internal`, `.corp`, `.intranet`, `.local`, `.private`.
- Private address references in URLs for `10.*`, `172.16-31.*`, and `192.168.*` subnets.
- common token prefixes such as `ghp_`, `ghs_`, `glpat-`, `AKIA`, `ASIA`, `xoxb-`, `xoxp-`, `xoxs-`, and `SG.`

### Methods

#### `SecretScanner.scan(text, secret_action: "alert", custom_patterns: [])`

Runs the baseline secret scanner and applies custom regex patterns.

#### Return hash

- `:text` — output text, possibly redacted when `secret_action: "redact"`.
- `:leaked` — boolean marker.
- `:findings` — array of findings with `category` and `matched`.

#### `secret_action` modes

- `alert` — leaves the original text intact.
- `redact` — replaces matched text excerpts with `[REDACTED]`.
- `block` — raises `SecretScanner::Blocked` when secrets are present.

### `SecretScanner::Blocked`

Exception class raised when `secret_action` is set to `block`.

- `#findings` returns the secret detection details.

## Error handling and developer expectations

- `Olyx::Guardrails.check` handles secret blocking internally and returns a normalized hash instead of raising.
- Use `SecretScanner.scan` directly when you need the raw block exception.
- Custom patterns are compiled with `Regexp.new(pattern, Regexp::IGNORECASE)` and invalid patterns are skipped.

## Example integration

```ruby
require "olyx/guardrails"

input = "Send this request to https://api.internal/v1 with token ak_live_123456"
result = Olyx::Guardrails.check(input, secret_action: "block")

if result[:allowed]
  # safe to proceed
else
  # handle unsafe input
end
```

## Notes

- The library is intentionally standalone and avoids Rails-specific dependencies.
- It is suitable for embedding in API middleware, CLI tools, or pre-processing pipelines.
