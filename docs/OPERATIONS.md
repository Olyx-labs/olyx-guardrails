# Operations and Production Behavior

This guide describes failure handling, telemetry, notification delivery, data
flow, and runtime limits.

After reading this guide, the reader will know:

- how deterministic and LLM results affect a decision;
- how provider failures behave;
- which content can leave the process;
- how notification failures are isolated; and
- which operational capabilities require an application or external platform.

## Evaluation order

`Guardrails.check` evaluates one input in this order:

1. convert the input with `to_s`;
2. run the length check;
3. when length permits, run PII, injection, secret, and policy checks;
4. when configured, call the LLM provider;
5. merge additive LLM findings;
6. calculate the risk score; and
7. return the decision.

An oversized input returns a rejected decision. Content scanners and the LLM
provider do not run, and their check entries contain `skipped: true`.

`Guardrails.redact` differs intentionally: oversized input raises
`ArgumentError` instead of performing a potentially unbounded transformation.

## Risk score

The deterministic score uses fixed heuristic weights:

| Signal | Weight |
|---|---:|
| Injection attempt | 0.50 |
| Secret | 0.25 |
| Restricted-policy finding | 0.25 |
| PII | 0.10 |
| Any blocked check | 0.15 |

The sum is clamped to `0.0..1.0` and rounded to four decimal places.

When an LLM provider returns a finite Numeric `risk_score`, the final score is
the greater of the deterministic score and the provider score. Provider scores
are clamped to `0.0..1.0`. Numeric strings, other invalid values, infinite
values, and NaN are ignored.

The score is a prioritization heuristic. It is not a probability, model
confidence, or calibrated measure of harm.

## LLM provider failure modes

The policy controls provider failures:

| Mode | Behavior |
|---|---|
| `:allow` | Preserve the deterministic decision and record the error under `llm_analysis` |
| `:block` | Add a rejected `llm` check and return `allowed: false` |
| `:raise` | Raise `Olyx::Guardrails::LlmProviderError` |

The default is `:allow`. Use `:block` or `:raise` when semantic analysis is a
required control.

Provider exceptions and malformed results become a bounded error:

```ruby
{
  llm_analysis: {
    error: "bounded error message"
  }
}
```

Provider errors cannot clear deterministic findings. Provider Boolean fields
must be literal `true` or `false`. Unknown result fields are discarded, and
the optional reason is bounded to 500 characters.

The gem does not retry provider calls. The application-owned provider adapter
defines connection timeouts, request timeouts, retries, circuit breakers, and
capacity limits.

## Data flow

Core deterministic checks run in-process and do not perform network requests.

An `llm_provider` receives raw input. For structured messages, it receives the
message text joined with newlines. Configuring a remote provider therefore
creates an application-owned data-egress path.

Before enabling a remote provider, establish:

- permitted data classifications;
- data residency and retention requirements;
- provider authentication and transport security;
- request and response logging rules;
- timeouts, retries, and circuit-breaker behavior; and
- a versioned model and prompt evaluation threshold.

Prefer a local or private classifier when raw input must remain inside the
application trust boundary.

## Model suitability

The callable provider boundary has no vendor, endpoint, or model allowlist. An
adapter may call a local model, open-source inference runtime, managed endpoint,
or internal gateway. Hashes and schema-model objects that implement
`deep_to_h` or `to_h` normalize to the same result contract.

Transport compatibility does not establish that a model is suitable for
blocking decisions. Do not choose a production minimum from parameter count,
advertised JSON support, or one successful response. Version the exact model,
prompt, and adapter, then require representative evaluation thresholds for:

- false negatives on the application's restricted inputs;
- false positives on ordinary application traffic;
- literal Boolean and bounded numeric output;
- malformed, missing, and contradictory fields;
- adversarial prompt and encoding variants;
- latency under expected concurrency; and
- failure and recovery behavior at capacity.

A small, untested, or inconsistently structured model remains useful for
monitoring experiments. It should not become the minimum blocking control only
because the adapter can convert one response to the provider schema.

## Notification delivery

Create a notifier with the same policy used for evaluation:

```ruby
notifier = Olyx::Guardrails::Notifier.new(
  policy: policy,
  handlers: {
    audit: ->(event) { AuditLog.write(event) },
    queue: ->(event) { GuardrailNotificationJob.perform_later(event) }
  }
)

delivery = notifier.notify(
  result,
  input: input,
  metadata: { request_id: request_id }
)
```

`notify` requires a decision Hash containing a finite Numeric `risk_score` from
`0.0` through `1.0`, plus Hash metadata. Invalid caller arguments raise
`ArgumentError`. It returns `nil` only when a valid decision has zero risk.
Otherwise it builds one deeply frozen event and sends the same object to every
handler.

Handlers run synchronously and independently. One exception does not prevent
later handlers from running. Use a queue handler when delivery should not add
latency to the request.

Constructor and caller-contract errors raise `ArgumentError`. Event-building
and handler errors are returned as delivery failures.

```ruby
{
  success: false,
  event: Hash,
  deliveries: [
    {
      handler: "audit",
      success: false,
      error: "bounded and redacted error"
    }
  ]
}
```

When event construction fails before an event exists, the result is:

```ruby
{
  success: false,
  error: "bounded and redacted error",
  deliveries: []
}
```

## Notification event

The event schema is versioned independently from the gem:

```ruby
{
  schema_version: 1,
  event: "guardrail.violation",
  policy_name: "production",
  allowed: false,
  risk_score: 0.75,
  violations: ["injection_attempt"],
  policy_rule_count: 0,
  metadata: {
    "request_id" => "request-123"
  },
  llm_reason: "Optional sanitized reason",
  input_preview: "Optional sanitized preview"
}
```

`llm_reason` is present only when the provider returned a reason.
`input_preview` is present only when `input:` was supplied.

Sanitization applies the notifier policy's:

- restricted-content replacements;
- custom secret patterns;
- built-in secret detection; and
- built-in PII redaction.

Additional bounds are:

| Field | Limit |
|---|---:|
| Policy name | 100 characters |
| LLM reason | 300 characters after sanitization |
| Input preview | 300 characters plus a truncation marker |
| Metadata entries | 20 |
| Metadata key | 50 characters |
| Metadata value | 300 characters after sanitization |
| Handler error | 300 characters after sanitization |
| Handlers per notifier | 20 |

Metadata keys normalize to letters, numbers, underscores, periods, and
hyphens. Colliding keys receive a numeric suffix instead of overwriting an
earlier value.

Sanitized previews are operational context, not proof that arbitrary plaintext
is safe to export. Configure notification destinations according to the
application's data-handling policy.

## Violation labels

Decision summaries and notifications use these stable labels:

| Condition | Label |
|---|---|
| Injection finding | `injection_attempt` |
| Secret finding | `secret_leaked` |
| PII finding | `pii_detected` |
| Restricted policy finding | `restricted_content` |
| Length rejection | `input_length_exceeded` |
| LLM provider failure in block mode | `provider_error` |

When a notifier receives a non-zero-risk result without a known label, it uses
`policy_violation`.

## Rails instrumentation

The Rails adapter publishes content-free Active Support events. Check,
violation, redaction, and notification payloads exclude:

- input and output text;
- findings and matched text;
- notification previews;
- application metadata;
- handler errors; and
- LLM reasoning.

Instrumentation subscriber exceptions are rescued and logged by class name.
They do not change an enforcement decision. See the
[Rails integration guide](RAILS.md#active-support-instrumentation) for event
names and payload contracts.

## Concurrency

Policies, policy rules, result summaries, and notification events are
immutable. A policy can be shared across threads.

Provider callables and notification handlers are supplied by the application.
They must be safe for the concurrency model of the host process. The gem does
not serialize calls to stateful adapters.

Rails configuration freezes after application initialization. Deploy policy
changes through configuration and restart the application rather than mutating
shared runtime state.

## Detection limits

### Prompt injection

Detection includes known structural tags and jailbreak phrases. It checks
bounded variants produced by:

- Unicode NFKC normalization;
- common Greek and Cyrillic homoglyph folding;
- zero-width character removal; and
- one layer each of URL, HTML entity, Unicode escape, and Base64 decoding.

It can miss paraphrasing, translation, unsupported homoglyphs, stacked
encoding, and new attack strategies.

### Secrets

Detection covers documented credential formats, JWTs, PEM private keys,
credential-bearing database URLs, confidentiality markers, and private network
endpoints. It cannot classify every high-entropy value or future provider
format.

### PII

Detection includes email, formatted and international phone numbers,
structurally valid U.S. SSNs, Luhn-valid Canadian SINs, Luhn-valid payment
cards, valid IP addresses, contextual passports, checksum-valid IBANs, and
calendar-valid contextual dates of birth.

Coverage is not a complete international PII taxonomy.

### Restricted content

Policy rules are deterministic. They do not infer translations, synonyms, or
semantic equivalents unless those forms are configured or an application
implements a separate semantic decision.

## Application and platform responsibilities

The gem intentionally does not provide:

- token-stream interception;
- model proxying or provider routing;
- file parsing or malware scanning;
- distributed rate or quota enforcement;
- centralized policy rollout;
- durable audit retention;
- fleet-wide analytics; or
- managed notification retries.

These responsibilities belong to application infrastructure or an external
control plane. The gem remains useful independently because its policy,
decision, redaction, notification, and Rails contracts do not require such a
platform.

## Production checklist

Before deployment:

1. define an explicit production policy;
2. cover every application-owned input and completed-output boundary;
3. choose `llm_failure_mode` deliberately;
4. set bounded provider and upload extraction timeouts;
5. test notification handler failures;
6. subscribe to content-free Rails instrumentation where applicable;
7. run representative false-negative and false-positive evaluations;
8. document unsupported PII, secret, and language formats; and
9. keep authorization and access control independent from guardrail findings.
