# Olyx Guardrails

[![Gem Version](https://badge.fury.io/rb/olyx-guardrails.svg)](https://rubygems.org/gems/olyx-guardrails)
[![Test](https://github.com/Olyx-labs/olyx-guardrails/actions/workflows/test.yml/badge.svg)](https://github.com/Olyx-labs/olyx-guardrails/actions/workflows/test.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Olyx-labs/olyx-guardrails/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Olyx-labs/olyx-guardrails)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Olyx Guardrails is an in-process safety boundary for Ruby and Rails
applications that send or receive AI-generated content. It provides:

- PII and secret detection with explicit redaction;
- prompt-injection and jailbreak detection, including adjacent-turn checks;
- immutable, organization-specific restricted-content policies;
- completed-input and completed-output decisions;
- opt-in Rails adapters for common ingestion paths;
- provider-agnostic semantic analysis through a callable LLM hook; and
- sanitized notifications and Active Support instrumentation.

The deterministic checks run locally. The gem does not proxy model traffic,
discover model calls, or send application content to a third party.

## Requirements

| Component | Supported versions |
|---|---|
| Ruby | 3.4 or newer |
| Rails | 8.0 and 8.1 |

Rails is optional. The standalone Ruby API does not load Rails.

The 1.1 release supports Rails 8.0 and 8.1. Only the listed Rails
series are tested and supported. When a series reaches upstream end-of-life,
a subsequent gem release may remove it instead of maintaining framework
security fixes independently. Every support change is recorded in the
changelog.

## Installation

Add the gem to the application:

```ruby
gem "olyx-guardrails", "~> 1.1"
```

Then install the bundle:

```bash
bundle install
```

The only runtime gem dependency is Ruby's `base64` bundled gem, used for
bounded encoded-input detection.

## Quick start

Create one immutable policy and use it at the application boundary:

```ruby
require "olyx/guardrails"

policy = Olyx::Guardrails::Policy.new(
  name: "customer-data-boundary",
  max_input_length: 4_000,
  block_pii: false,
  block_injections: true,
  block_secrets: true,
  rules: [
    {
      name: :confidential_projects,
      terms: ["Project Falcon"],
      match: :whole_word,
      block: true,
      replacement: "[CONFIDENTIAL_PROJECT]"
    }
  ]
)

decision = Olyx::Guardrails.check(input, policy: policy)
return forbidden unless decision[:allowed]

safe_input = Olyx::Guardrails.redact(input, policy: policy)[:text]
completion = LlmClient.complete(safe_input)

output_decision = Olyx::Guardrails.check_output(completion, policy: policy)
return invalid_output unless output_decision[:allowed]
```

`check` makes a decision and never transforms input. `redact` transforms
recognized content and never makes an allow/block decision. Applications that
need both operations call both explicitly.

The default policy:

- limits input to 10,000 characters;
- blocks detected injection attempts;
- reports, but does not block, detected PII and secrets; and
- has no custom restricted-content rules.

Production applications should construct an explicit policy instead of relying
on defaults. See the [Policies guide](docs/POLICIES.md) for the complete rule
language and YAML examples.

## Rails quick start

Generate an initializer and environment-keyed policy file:

```bash
bin/rails generate olyx_guardrails:install
```

Add the controller concern only where content crosses an AI boundary:

```ruby
class AiRequestsController < ApplicationController
  include Olyx::Guardrails::Rails::Controller

  rescue_from Olyx::Guardrails::Blocked do |error|
    render json: {
      error: "input_rejected",
      decision: error.decision
    }, status: :unprocessable_entity
  end

  def create
    prompt = params.require(:prompt)
    guardrails_check!(prompt, metadata: { user_id: current_user.id })

    safe_prompt = guardrails_redact(prompt)[:text]
    completion = LlmClient.complete(safe_prompt)
    Olyx::Guardrails::Rails::Enforcer.check_output!(completion)

    render json: { completion: completion }, status: :created
  end
end
```

Rails enforcement is opt-in. The gem does not scan parameters, callbacks,
uploads, jobs, GraphQL operations, or Action Cable messages globally.

The [Rails integration guide](docs/RAILS.md) covers every adapter, boot-time
configuration, safe YAML loading, instrumentation payloads, and notification
delivery.

## Choose the right entry point

| Boundary | Entry point | Behavior |
|---|---|---|
| Plain text input | `Guardrails.check` | Returns an allow/block decision |
| Structured messages | `Guardrails.check_messages` | Adds adjacent-turn detection |
| Completed model output | `Guardrails.check_output` | Explicit output decision |
| Plain text transformation | `Guardrails.redact` | Returns redacted text |
| Completed output transformation | `Guardrails.redact_output` | Explicit output transformation |
| Rails exception flow | `Rails::Enforcer.check!` | Raises `Guardrails::Blocked` when rejected |
| Low-level secret enforcement | `SecretScanner.scan!` | Raises `SecretScanner::Blocked` on a finding |

All completed-output methods operate on complete values. They do not inspect a
token stream before content reaches the caller.

## Optional LLM provider

`llm_provider` accepts any callable object. It receives the raw text and a
bounded context hash containing deterministic findings:

```ruby
provider = lambda do |text, context|
  LocalClassifier.call(text: text, signals: context)
end

policy = Olyx::Guardrails::Policy.new(llm_failure_mode: :block)

result = Olyx::Guardrails.check(
  input,
  policy: policy,
  llm_provider: provider
)
```

The provider returns a hash or schema object containing any of:

```ruby
{
  injection_attempt: false,
  pii_detected: false,
  secret_leaked: false,
  risk_score: 0.2,
  reason: "No semantic violation found"
}
```

The gem owns normalization, validation, failure handling, and safe result
merging. The application owns model selection, prompting, authentication,
timeouts, retries, and transport. LLM analysis findings can add a violation but cannot clear a deterministic finding.

See the [provider contract](docs/API.md#llm-provider-contract) and the
[local HTTP example](examples/local_llm_provider.rb). The example works with
an application-owned classifier sidecar backed by any inference runtime. Read
the [model-suitability criteria](docs/OPERATIONS.md#model-suitability) before
using semantic analysis as a blocking production control.

## Documentation

- [Documentation index](docs/README.md)
- [Policies and restricted content](docs/POLICIES.md)
- [Rails integration](docs/RAILS.md)
- [Operations and production behavior](docs/OPERATIONS.md)
- [API reference](docs/API.md)
- [Release runbook](docs/RELEASING.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

Examples:

- [Framework-free Ruby](examples/ruby_only.rb)
- [Custom policy](examples/custom_policy.rb)
- [Rails opt-in boundaries](examples/rails_opt_in.rb)
- [Local LLM provider](examples/local_llm_provider.rb)
- [Notifier handlers](examples/notifier.rb)

The framework-free, custom-policy, and notifier examples run directly. The
Rails example is application-context code, and the local provider example
expects the documented classifier sidecar.

## Security model and limitations

Olyx Guardrails is a defense-in-depth control, not a complete semantic security
boundary or data-loss-prevention system.

- Pattern-based detection can miss paraphrasing, translations, novel attacks,
  unsupported homoglyphs, and nested encoding beyond the bounded normalization
  pass.
- PII support is strongest for documented North American and common
  international formats.
- Secret detection is format-based and cannot classify every high-entropy
  string or future credential format.
- Restricted-content rules are deterministic unless an application supplies an
  LLM provider.
- File parsing, authorization, streaming enforcement, distributed quotas,
  centralized policy rollout, and audit retention remain application or
  platform responsibilities.

The [operations guide](docs/OPERATIONS.md) describes failure modes, data
handling, risk scores, concurrency, and deployment boundaries. Report security
issues through [SECURITY.md](SECURITY.md), not the public issue tracker.

## Development

Run the same gates used by CI:

```bash
bin/setup
bin/ci
```

The development bundle includes Rails so contributors exercise the integration
from the default test suite; Rails remains an optional runtime dependency for
gem consumers. The Rails compatibility matrix is managed with Appraisal. See
[CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change.

## License

Olyx Guardrails is available under the
[Apache License 2.0](LICENSE).
