# Olyx Guardrails

[![RubyGems](https://img.shields.io/gem/v/olyx-guardrails?label=rubygems)](https://rubygems.org/gems/olyx-guardrails)
[![Release](https://img.shields.io/github/v/release/Olyx-labs/olyx-guardrails?label=release)](https://github.com/Olyx-labs/olyx-guardrails/releases/latest)
[![Test](https://github.com/Olyx-labs/olyx-guardrails/actions/workflows/test.yml/badge.svg)](https://github.com/Olyx-labs/olyx-guardrails/actions/workflows/test.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Olyx-labs/olyx-guardrails/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Olyx-labs/olyx-guardrails)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

In-process AI guardrails for Ruby and Rails. Detect, decide, and redact at the
application boundary without proxying model traffic or sending content to Olyx.

## Features

- Detects PII, secrets, prompt injection, and multi-turn attacks.
- Enforces immutable custom content policies.
- Checks completed model inputs and outputs.
- Adds opt-in Rails adapters, notifications, and instrumentation.
- Accepts an application-owned LLM hook for semantic analysis.

Deterministic checks run locally. Rails and semantic analysis are optional.

## Requirements

| Component | Supported versions |
|---|---|
| Ruby | 3.4 or newer |
| Rails | 8.0 and 8.1 |

## Installation

Add the gem to your `Gemfile`:

```ruby
gem "olyx-guardrails", "~> 1.2"
```

Then run `bundle install`.

## Usage

```ruby
require "olyx/guardrails"

policy = Olyx::Guardrails::Policy.new(
  name: "ai-boundary",
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

decision = Olyx::Guardrails.check(prompt, policy: policy)
return forbidden unless decision[:allowed]

safe_prompt = Olyx::Guardrails.redact(prompt, policy: policy)[:text]
completion = LlmClient.complete(safe_prompt)

output = Olyx::Guardrails.check_output(completion, policy: policy)
return invalid_output unless output[:allowed]
```

`check` returns a decision without changing content. `redact` transforms
recognized content without making an allow/block decision. Call both when you
need both behaviors.

The default policy limits input to 10,000 characters, blocks injection, reports
PII and secrets, and defines no custom rules. Use an explicit policy in
production. See the [policy guide](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/POLICIES.md)
for all options.

### Rails

Generate the initializer and policy file:

```bash
bin/rails generate olyx_guardrails:install
```

Opt in only at controllers or other boundaries that handle AI content:

```ruby
class AiRequestsController < ApplicationController
  include Olyx::Guardrails::Rails::Controller

  rescue_from Olyx::Guardrails::Blocked do |error|
    render json: { error: "input_rejected", decision: error.decision },
           status: :unprocessable_entity
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

The gem never scans Rails requests globally. See the
[Rails guide](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/RAILS.md)
for controllers, jobs, GraphQL, Action Cable, uploads, and instrumentation.

### Entry points

| Boundary | Method |
|---|---|
| Plain text input | `Guardrails.check` |
| Structured messages | `Guardrails.check_messages` |
| Completed model output | `Guardrails.check_output` |
| Plain text redaction | `Guardrails.redact` |
| Completed output redaction | `Guardrails.redact_output` |
| Rails exception flow | `Rails::Enforcer.check!` |

Output methods operate on complete values; they do not inspect token streams.

### Optional semantic analysis

Pass any callable as `llm_provider`:

```ruby
provider = lambda do |text, context|
  LocalClassifier.call(text: text, signals: context)
end

result = Olyx::Guardrails.check(
  prompt,
  policy: Olyx::Guardrails::Policy.new(llm_failure_mode: :block),
  llm_provider: provider
)
```

The application owns model selection, credentials, transport, timeouts, and
retries. Provider results can add findings but cannot clear deterministic
findings. See the
[provider contract](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/API.md#llm-provider-contract).

## Security scope

Olyx Guardrails is a defense-in-depth control, not a complete semantic security
boundary or data-loss-prevention system.

- Pattern matching can miss novel, translated, or deeply encoded attacks.
- PII and secret detection cover documented formats, not every possible value.
- File parsing, authorization, streaming enforcement, quotas, centralized
  rollout, and audit retention remain application responsibilities.

See the [operations guide](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/OPERATIONS.md)
for production guidance. Report vulnerabilities through the
[security policy](https://github.com/Olyx-labs/olyx-guardrails/security/policy).

## Documentation

- [Documentation index](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/README.md)
- [Policies](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/POLICIES.md)
- [Rails integration](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/RAILS.md)
- [API reference](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/API.md)
- [Framework-free example](https://github.com/Olyx-labs/olyx-guardrails/blob/master/examples/ruby_only.rb)
- [Changelog](CHANGELOG.md)
- [Contributing](https://github.com/Olyx-labs/olyx-guardrails/blob/master/CONTRIBUTING.md)

## Development

```bash
bin/setup
bin/ci
```

Rails adapter changes must also pass `bundle exec appraisal rake test`. See
[Contributing](https://github.com/Olyx-labs/olyx-guardrails/blob/master/CONTRIBUTING.md)
for the complete workflow.

## License

Olyx Guardrails is available under the [Apache License 2.0](LICENSE).
