# Olyx Guardrails

[![Gem Version](https://badge.fury.io/rb/olyx-guardrails.svg)](https://rubygems.org/gems/olyx-guardrails)
[![Test](https://github.com/mosesnjoroge/olyx-guardrails/actions/workflows/test.yml/badge.svg)](https://github.com/mosesnjoroge/olyx-guardrails/actions/workflows/test.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/mosesnjoroge/olyx-guardrails/badge)](https://securityscorecards.dev/viewer/?uri=github.com/mosesnjoroge/olyx-guardrails)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`olyx-guardrails` is a dependency-light Ruby library for synchronous AI
boundary safety:

- PII and credential redaction
- Prompt-injection and jailbreak detection
- Secret and internal-endpoint detection
- Input-length enforcement
- Reusable named policies for organization-specific restricted content
- Structured-message checks and completed-output checks
- Optional semantic analysis through a caller-supplied AI hook
- Optional OpenAI Responses API connector with native schema models
- Vendor-neutral notifications through configurable application handlers

The core checks run in-process and have no runtime gem dependencies.

## Installation

```ruby
gem "olyx-guardrails", "~> 1.0"
```

```bash
bundle install
```

Ruby 3.4 or newer is required. The repository pins the current Ruby 3.4 patch
release in `.ruby-version` for rbenv users.

## Choose an integration path

- [`examples/ruby_only.rb`](examples/ruby_only.rb) is a runnable, framework-free
  example with custom policy enforcement, redaction, completed-output checks,
  and vendor-neutral notifications.
- [`examples/rails_opt_in.rb`](examples/rails_opt_in.rb) shows explicit Rails
  boundaries for controllers, GraphQL, Action Cable, Active Job, Active Model,
  uploads, callbacks, and service objects.

The Ruby-only path requires no Rails runtime. The Rails path remains opt-in and
uses the same core `Policy` and decision contracts.

## Rails integration

The core gem remains framework-neutral. Rails applications receive an optional
Railtie, boot-validated configuration, explicit adapters for controllers,
GraphQL, Action Cable, Active Job, Active Model, uploads, and service objects,
sanitized Active Support events, filtered AI parameter names, and an Active Job
notifier adapter. Enforcement remains opt-in: the gem never guesses which
application values are AI-bound.

Install the Rails configuration:

```bash
bin/rails generate olyx_guardrails:install
```

This creates `config/initializers/olyx_guardrails.rb` and an environment-keyed
`config/olyx_guardrails.yml`. YAML is loaded with `YAML.safe_load`; ERB,
aliases, arbitrary classes, and symbols are not evaluated. A missing,
unreadable, unsafe, or invalid configured policy stops application boot instead
of falling back to a permissive policy.

Use the explicit controller concern at the AI boundary:

```ruby
class AiRequestsController < ApplicationController
  include Olyx::Guardrails::Rails::Controller

  rescue_from Olyx::Guardrails::Blocked do |error|
    render json: { error: "input_rejected", decision: error.decision },
      status: :unprocessable_entity
  end

  def create
    guardrails_check!(
      params.require(:prompt),
      metadata: { user_id: current_user.id }
    )
    safe_prompt = guardrails_redact(params[:prompt])[:text]

    render json: LlmClient.complete(safe_prompt), status: :created
  end
end
```

The exception contains a frozen decision summary—policy name, risk score,
violation labels, and restricted rule identifiers—but never the input or AI
reason. The application owns the HTTP response because `403`, `422`, and other
policies have different semantics.

Protect the other common Rails ingress paths explicitly:

```ruby
class CompletionResolver
  include Olyx::Guardrails::Rails::GraphQL

  def resolve(prompt:)
    guardrails_check_graphql!(prompt)
    result = LlmClient.complete(prompt)
    guardrails_check_graphql_output!(result)
    result
  end
end

class PromptChannel < ApplicationCable::Channel
  include Olyx::Guardrails::Rails::ActionCable

  def receive(data)
    guardrails_check_cable!(data.fetch("prompt"))
  end
end

class CompletionJob < ApplicationJob
  include Olyx::Guardrails::Rails::Job
  guardrails_input_arguments 0, :system_prompt
end

class PromptDraft
  include ActiveModel::Model
  attr_accessor :prompt
  validates :prompt, olyx_guardrails: true
end
```

For callbacks and service objects, call
`Olyx::Guardrails::Rails::Enforcer.check!`, `check_messages!`, or
`check_output!`. For uploads, the application retains ownership of parsing and
passes a bounded text extractor:

```ruby
Olyx::Guardrails::Rails::Upload.check!(
  params.require(:document),
  extractor: ->(upload) { DocumentText.extract(upload.tempfile) }
)
```

These adapters close framework routing gaps; they do not parse arbitrary file
formats, discover model calls, or intercept every callback automatically.

Rails checks publish content-free Active Support events:

```ruby
ActiveSupport::Notifications.subscribe("violation.olyx_guardrails") do |event|
  Rails.logger.warn(event.payload.to_json)
end
```

Available events are `check.olyx_guardrails`, `violation.olyx_guardrails`,
`redact.olyx_guardrails`, and `notification.olyx_guardrails`. They include
bounded decision or delivery fields and evaluation duration, never raw input,
redacted output, metadata, or analyzer prose. Subscriber failures are isolated
from enforcement.

Use any Active Job backend for asynchronous notification delivery:

```ruby
Olyx::Guardrails::Rails.configure do |config|
  config.policy_path = Rails.root.join("config/olyx_guardrails.yml")
  config.notifier_handlers = {
    incidents: Olyx::Guardrails::Rails::ActiveJobHandler.new(
      job: "GuardrailIncidentJob",
      queue: :low
    )
  }
end
```

The String job name is resolved when the event is delivered, which remains
compatible with Rails code reloading. The job receives the same sanitized,
immutable vendor-neutral event described under Notifications.

## Configure a reusable policy

All enforcement settings and organization-specific restrictions live in one
immutable policy object:

```ruby
require "olyx/guardrails"

POLICY = Olyx::Guardrails::Policy.new(
  name:               "customer-data-boundary",
  max_input_length:   4_000,
  block_pii:          true,
  block_injections:   true,
  block_secrets:      true,
  ai_failure_mode:    :block,
  secret_patterns:    ["company-token-[a-z0-9]{24}"],
  rules: [
    {
      name:        :confidential_projects,
      description: "Project names that must not enter an AI request",
      patterns:    ["project[ -]falcon", /PF-\d{4}/],
      block:       true,
      replacement: "[CONFIDENTIAL_PROJECT]"
    },
    {
      name:        :competitor_references,
      terms:       ["competitor corp"],
      match:       :whole_word,
      block:       false
    }
  ]
)
```

Use `terms` for literal, case-insensitive restricted text; regex metacharacters
inside a term are escaped automatically. `match:` controls term interpretation:
`:substring` (default), `:whole_word`, or `:regexp`. String `patterns` are always
regular-expression source and compiled case-insensitively, while `Regexp`
patterns retain their flags. Each rule must define at least one term or pattern.
A blocking rule makes `check` reject the input; a non-blocking rule records the
violation for monitoring. `redact` transforms matches from either kind. Rule
configuration is compiled once when the policy is created, rejects
empty-matching or invalid expressions, and applies a timeout during matching.

`ai_failure_mode:` controls an optional analyzer failure: `:allow` keeps the
deterministic decision (the default), `:block` adds a failed AI check and rejects
the request, and `:raise` raises `Olyx::Guardrails::AiAnalyzerError`. Production
applications that require semantic analysis should choose `:block` or `:raise`
explicitly.

String-keyed configuration loaded from YAML or JSON is supported:

```ruby
policy = Olyx::Guardrails::Policy.from_h(configuration)
```

Policy findings are separate from secret findings. They expose the rule name,
description, block decision, `[REDACTED]` marker, SHA-256 fingerprint, and offsets;
the matched restricted text is never returned in plaintext.
Use `secret_patterns` for organization-specific credential formats that should
remain classified as secrets; use `rules` for business restrictions.
See [`examples/custom_policy.rb`](examples/custom_policy.rb) for a complete
decision-and-redaction flow.

## Decision and transformation are separate

Use `check` to make an allow/block decision:

```ruby
require "olyx/guardrails"

result = Olyx::Guardrails.check(
  input,
  policy: POLICY
)

return forbidden unless result[:allowed]
```

Use `redact` when transformed text is required:

```ruby
redaction = Olyx::Guardrails.redact(input, policy: POLICY)

safe_input = redaction[:text]
redaction[:redacted]      # true when text changed
redaction[:pii_detected]  # true when regex-detected PII was removed
redaction[:secret_leaked] # true when a secret was removed
```

`check` never claims to transform input, and `redact` never makes an
allow/block decision.

Use structured messages when adjacent turns matter, and explicit output names
at the completed model boundary:

```ruby
message_result = Olyx::Guardrails.check_messages(
  [{role: "user", content: prompt}, {role: "assistant", content: draft}],
  policy: POLICY
)

output_result = Olyx::Guardrails.check_output(completion, policy: POLICY)
safe_output = Olyx::Guardrails.redact_output(completion, policy: POLICY)[:text]
```

`check_output` and `redact_output` operate on completed values. They are
deliberately distinct entry-point names so applications can instrument input
and output boundaries without implying token-stream enforcement.

## `Olyx::Guardrails.check`

```ruby
Olyx::Guardrails.check(
  input,
  policy: Olyx::Guardrails::Policy.default,
  ai_analyzer: nil
)
```

| Option | Type | Default | Description |
|---|---|---|---|
| `input` | any | — | Converted via `to_s` |
| `policy` | `Olyx::Guardrails::Policy` | `Policy.default` | Limits, built-in blocking behavior, and named restricted-content rules |
| `ai_analyzer` | callable or nil | `nil` | Optional semantic analyzer |

`Policy.default` preserves the built-in defaults: 10,000-character input limit,
block injections, flag PII and secrets, and no custom restricted-content
rules. Invalid policy configuration raises `ArgumentError` when the policy is
constructed; mistakes do not silently degrade into an allow decision.

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
  checks: [
    { type: "pii",       allowed: true,    detected: Boolean },
    { type: "injection", allowed: Boolean, injection_attempt: Boolean, patterns: Array },
    { type: "secret",    allowed: Boolean, leaked: Boolean, count: Integer },
    { type: "policy",    allowed: Boolean, violated: Boolean, count: Integer, findings: Array },
    { type: "length",    allowed: Boolean, length: Integer, max_length: Integer }
  ],
  ai_analysis: Hash # only when ai_analyzer is supplied and runs
}
```

The length check runs first. When it fails, content and AI checks are skipped and
content checks carry `skipped: true`.

## `Olyx::Guardrails.redact`

```ruby
Olyx::Guardrails.redact(
  input,
  policy: Olyx::Guardrails::Policy.default
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
  policy_name:     String,
  policy_violated: Boolean,
  policy_findings: Array<Hash>,
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
hook exceptions are recorded under `result[:ai_analysis][:error]`; the policy's
`ai_failure_mode` then allows the deterministic result, blocks, or raises. AI
findings can add a violation but cannot clear one.

The hook receives raw input. If it calls a third-party model, the caller is
responsible for data-residency, privacy, and vendor-trust requirements.
The context includes locally matched `policy_violated` and `policy_rules`
signals, but the analyzer result contract does not invent custom policy
matches. Organization rules in this release remain deterministic; applications
that require semantic topic policy should make that separate decision explicit
rather than relabeling it as injection, PII, or a secret.

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
This low-level option extends credential detection and reports matches as
secrets. Use `PolicyRule` for business restrictions so findings retain a name,
description, block decision, and distinct `policy` classification.

## Risk score

The heuristic score is injection (`0.50`) + secret (`0.25`) + restricted-policy
match (`0.25`) + PII (`0.10`) + any blocked check (`0.15`), clamped to
`0.0..1.0`. It supports graduated responses; it is not a probability or
calibrated model confidence.

## Notifications

```ruby
notifier = Olyx::Guardrails::Notifier.new(
  policy: POLICY,
  handlers: {
    audit_log: ->(event) { Rails.logger.warn(event.to_json) },
    incident_queue: ->(event) { IncidentNotificationJob.perform_later(event) }
  }
)

notifier.notify(
  result,
  input:    input,
  metadata: { user_id: current_user.id, endpoint: request.path }
)
```

Pass the same policy used by `Guardrails.check`. Each named handler receives the
same frozen, vendor-neutral event. A handler can write to a logger, enqueue a
job, send email, publish to a message bus, or invoke any incident/webhook SDK.
Handlers run synchronously and failures are isolated; enqueue work when delivery
must be asynchronous.

Input previews, AI reasons, metadata keys, metadata values, and handler errors
are bounded and redacted with the policy's restricted-content rules, custom
credential patterns, and the built-in PII and secret detectors.

## Limitations

- Pattern-based injection detection normalizes NFKC text, common Greek/Cyrillic
  homoglyphs, zero-width characters, and one bounded layer of URL, HTML-entity,
  Unicode-escape, or Base64 encoding. It can still miss paraphrasing,
  translation, nested/stacked encoding beyond one layer, unsupported
  homoglyphs, and new attack techniques.
- Secret coverage includes common cloud/SaaS tokens, JWTs, PEM private keys,
  credential-bearing database URLs, and private endpoints, but remains
  format-based and cannot reliably classify arbitrary high-entropy strings or
  every provider-specific credential. Coverage is intentionally not
  exhaustive — additional vendor token formats are a good first
  contribution; see [CONTRIBUTING.md](CONTRIBUTING.md).
- PII patterns remain biased toward common US/Western formats (plus
  Luhn-valid Canadian SIN). Broader international coverage is a good fit for
  a community PR rather than something this library tries to front-load.
- Restricted-content policies are pattern-based. They do not infer semantic
  equivalents, translations, or obfuscated terms unless explicitly configured.
- Completed-output APIs do not inspect streaming tokens before they reach the
  caller. Upload checks require caller-supplied text extraction.
- In-process decisions, notifications, and metrics are local to one Ruby
  process. The gem does not provide cross-service policy distribution, global
  quotas, centralized audit retention, managed retries, or fleet dashboards.
- Redaction addresses recognized data patterns; it is not a replacement for
  authorization or a complete data-loss-prevention system.

## Gem and Olyx Cloud boundary

The gem is intended to be useful on its own: deterministic checks, custom
policies, completed input/output enforcement, Rails boundary adapters, safe
local telemetry, and caller-owned notification handlers all run in the
application process.

Olyx Cloud is the operational control plane for teams that outgrow local
enforcement: a full LLM proxy route, centralized and versioned policy rollout,
cross-service audit and retention, distributed quotas, managed provider routing
and retries, streaming enforcement, fleet analytics, and managed asynchronous
delivery. Those distributed capabilities are intentionally not simulated by
the gem, so adopting the open-source library does not create a later migration
away from its public APIs.

## Development and security

```bash
bundle exec rake test
COVERAGE=true bundle exec rake test
bundle exec ruby script/flog_gate.rb
gem build olyx-guardrails.gemspec
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development expectations and
[SECURITY.md](SECURITY.md) for private vulnerability reporting. Everyone
interacting in this project's codebase, issue tracker, and other spaces is
expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

Apache-2.0. See [LICENSE](LICENSE).
