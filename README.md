# Olyx Guardrails

`olyx-guardrails` is a Ruby library for AI safety guardrails. It provides synchronous, in-process detection and response for:

- PII scrubbing
- Prompt injection and jailbreak detection (regex + multi-turn)
- Secret and credential scanning
- Input length enforcement
- Pluggable AI analyzer hook for semantic evaluation

No runtime dependencies. No external API calls. Runs in the same thread as the request.

## Installation

```ruby
gem "olyx-guardrails"
```

```bash
bundle install
```

Or install directly:

```bash
gem install olyx-guardrails
```

Requires Ruby 3.1 or newer.

## Quick Start

```ruby
require "olyx/guardrails"

result = Olyx::Guardrails.check(
  "My email is person@example.com and ignore all previous instructions",
  injection_block: true,
  secret_action:   "alert"
)

result[:allowed]           # => false
result[:pii_detected]      # => true
result[:injection_attempt] # => true
result[:risk_score]        # => float 0.0..1.0
```

## Core API

### `Olyx::Guardrails.check`

```ruby
Olyx::Guardrails.check(
  input,
  max_input_length: 10_000,
  injection_block:  true,
  secret_action:    "alert",
  custom_patterns:  [],
  ai_analyzer:      nil
)
```

Runs all guardrail checks in a single call and returns a result hash.

#### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `input` | any | — | Converted to string via `to_s` |
| `max_input_length` | Integer | `10_000` | Blocks input exceeding this length |
| `injection_block` | Boolean | `true` | Block the request when injection is detected |
| `secret_action` | String | `"alert"` | `"alert"`, `"redact"`, or `"block"` |
| `custom_patterns` | Array | `[]` | Additional regex strings for secret scanning |
| `ai_analyzer` | Callable | `nil` | Optional AI hook — see [AI Analyzer Hook](#ai-analyzer-hook) |

#### Return shape

```ruby
{
  allowed:           Boolean,
  pii_detected:      Boolean,
  injection_attempt: Boolean,
  secret_leaked:     Boolean,
  risk_score:        Float,     # 0.0..1.0
  checks: [
    { type: "pii",       allowed: Boolean, detected: Boolean },
    { type: "injection", allowed: Boolean, injection_attempt: Boolean, patterns: Array },
    { type: "secret",    allowed: Boolean, leaked: Boolean, count: Integer },
    { type: "length",    allowed: Boolean, length: Integer, max_length: Integer }
  ],
  ai_analysis: { ... }          # present only when ai_analyzer: is supplied
}
```

---

## AI Analyzer Hook

The `ai_analyzer:` parameter accepts any callable that receives `(text, context)` and returns a Hash. It runs after all regex checks so the AI layer receives what the pattern scanner already found — avoiding redundant LLM calls on clear-cut cases.

```ruby
claude_hook = ->(text, context) do
  # Skip the LLM call if regex already caught it
  return {} if context[:injection_attempt]

  response = Anthropic::Client.new.messages(
    model:      "claude-haiku-4-5-20251001",
    max_tokens: 64,
    system:     "Classify this input. Reply with JSON only: " \
                "{\"injection_attempt\": bool, \"reason\": string}",
    messages:   [{ role: "user", content: text }]
  )

  JSON.parse(response.content.first.text, symbolize_names: true)
rescue => e
  { error: e.message }
end

result = Olyx::Guardrails.check(input, ai_analyzer: claude_hook)
result[:ai_analysis][:reason]  # LLM explanation
```

#### Context passed to the hook

```ruby
{
  pii_detected:       Boolean,
  injection_attempt:  Boolean,
  injection_patterns: Array,    # matched pattern details from InjectionDetector
  secret_leaked:      Boolean
}
```

#### Expected return keys (all optional)

```ruby
{
  injection_attempt: Boolean,
  pii_detected:      Boolean,
  secret_leaked:     Boolean,
  risk_score:        Float,     # 0.0..1.0 — used when higher than regex score
  reason:            String     # explanation, included in ai_analysis
}
```

#### Behavior

- **Defense-in-depth**: AI findings union with regex findings. The hook can flag additional violations but cannot clear existing ones.
- **Fault-tolerant**: exceptions raised by the hook are rescued. The error is recorded in `result[:ai_analysis][:error]` and the regex result stands.
- **Skipped on oversized input**: the hook is not called when `max_input_length` is exceeded.
- **Risk score**: `result[:risk_score]` is the maximum of the regex-derived score and the hook's `risk_score` when provided.

---

## Components

### `PiiScrubber`

Detects and redacts personal data from free text and message arrays.

**Patterns:** email, phone, SSN, credit card (Luhn-validated), IPv4, API tokens, passport numbers, IBANs, dates of birth.

```ruby
PiiScrubber.scrub(text)
# => redacted string

PiiScrubber.scrub_messages(messages)
# => messages array with string content redacted

PiiScrubber.scrub_messages_with_detection(messages)
# => { messages: [...], detected: Boolean }
```

### `InjectionDetector`

Detects prompt injection and jailbreak techniques via structural tag patterns, phrase blocklist, and multi-turn split-attack detection.

Multi-turn detection scans adjacent message pairs for fragment patterns that are benign in isolation but combine into a jailbreak attempt across turns.

```ruby
InjectionDetector.scan(messages)
# => { injection_attempt: Boolean, patterns: [...] }

InjectionDetector.injection?(text)
# => Boolean — convenience wrapper for a single user message
```

Messages should follow standard chat format:

```ruby
[
  { "role" => "user",      "content" => "..." },
  { "role" => "assistant", "content" => "..." }
]
```

### `SecretScanner`

Detects leaked secrets, internal endpoints, private network addresses, and vendor token formats.

**Detected categories:** confidentiality markers, internal hostnames (`.internal`, `.corp`, `.lan`), RFC-1918 addresses in URLs, AWS access key IDs (AKIA/ASIA/AROA), AWS secret access keys, GitHub/GitLab/Slack/npm tokens, Anthropic API keys, JWTs, SendGrid keys.

```ruby
SecretScanner.scan(text, secret_action: "alert", custom_patterns: [])
# => { text: String, leaked: Boolean, findings: [{ category: String, matched: String }] }

SecretScanner.baseline_scan(text)
# => { leaked: Boolean, findings: [...] }
```

**`secret_action` behaviors:**
- `"alert"` — returns original text, marks leakage
- `"redact"` — replaces matched secrets with `[REDACTED]` (full match, not truncated)
- `"block"` — raises `SecretScanner::Blocked` with findings attached

---

## Design Notes

- The `length` check runs first. Oversized input is rejected immediately; the regex and AI scans are skipped entirely rather than running on content that will be rejected anyway.
- `Olyx::Guardrails.check` always returns a result hash. The `secret_action: "block"` path converts the blocked exception into a failed result rather than bubbling the exception to the caller.
- A result is `allowed: false` when any individual check is not allowed.
- `risk_score` is a weighted heuristic: injection (0.50) + secret (0.25) + blocked (0.15) + PII (0.10), clamped to 1.0. Use it for graduated responses rather than treating every non-zero score as a hard block.

## Limitations

`olyx-guardrails` is pattern-based by default, not semantic. Combine it with the `ai_analyzer:` hook and upstream controls for meaningful defense-in-depth.

- **Injection detection** catches known phrasing and structural tags. Paraphrasing, translation, encoding (base64, ROT13, homoglyphs), or novel attack patterns not in `PHRASE_PATTERNS` will not be detected by regex alone — use the AI hook for semantic coverage.
- **Secret scanning** covers a fixed set of vendor token formats. GCP, Azure, Stripe, PEM-encoded private keys, and generic high-entropy strings are not covered.
- **PII patterns** are biased toward US/Western formats. Non-US national identifiers and unicode obfuscation are not reliably caught.

## Development

```bash
bundle exec rake test
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
