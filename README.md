# Olyx Guardrails

[![RubyGems](https://img.shields.io/gem/v/olyx-guardrails?label=rubygems)](https://rubygems.org/gems/olyx-guardrails)
[![Release](https://img.shields.io/github/v/release/Olyx-labs/olyx-guardrails?label=release)](https://github.com/Olyx-labs/olyx-guardrails/releases/latest)
[![Test](https://github.com/Olyx-labs/olyx-guardrails/actions/workflows/test.yml/badge.svg)](https://github.com/Olyx-labs/olyx-guardrails/actions/workflows/test.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Olyx-labs/olyx-guardrails/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Olyx-labs/olyx-guardrails)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Input and output checks for AI applications in Ruby and Rails.

Detect prompt injection, PII, secrets, and application-specific restricted
content. Return explicit allow/block decisions and redact recognized content
at the boundaries your application chooses.

Olyx Guardrails is a standalone gem. It works without Olyx CLI, Olyx Cloud,
or an Olyx account. Deterministic checks run locally. An optional
`llm_provider` receives raw input and may send it elsewhere through your
application's adapter.

## Install

Requires **Ruby 3.4 or newer**. Rails is optional; the integration supports
**Rails 8.0 and 8.1**. The framework-free API does not load Rails.

Add to your `Gemfile`:

```ruby
gem "olyx-guardrails", "~> 1.2"
```

```sh
bundle install
```

The only runtime gem dependency is Ruby's bundled `base64` gem.

## Try it

Save this as `guardrails_example.rb`:

```ruby
require "olyx/guardrails"

policy = Olyx::Guardrails::Policy.new(
  name: "application-boundary",
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

input = "Contact ada@example.com about the release."
decision = Olyx::Guardrails.check(input, policy: policy)
abort "Input rejected" unless decision[:allowed]

puts "Allowed: #{decision[:allowed]}"
puts Olyx::Guardrails.redact(input, policy: policy)[:text]

restricted = Olyx::Guardrails.check("Discuss Project Falcon", policy: policy)
puts "Restricted input allowed: #{restricted[:allowed]}"
```

Run it:

```sh
bundle exec ruby guardrails_example.rb
```

Expected output:

```text
Allowed: true
Contact [EMAIL] about the release.
Restricted input allowed: false
```

In this policy, PII is reported without blocking, then explicitly redacted.
Injection attempts, secrets, and the configured project name cause rejection.
Policies are immutable: construct them once and reuse them.

**Checking and redacting are separate operations.** `check` returns a decision
without changing input. `redact` transforms recognized content without making
an allow/block decision. Redaction does not override a rejection.

Use `check_messages` for structured conversations and adjacent-turn detection.
Use `check_output` and `redact_output` at completed-output boundaries. Your
application owns the model call and must check the completed response before
returning it. See the [complete Ruby example](https://github.com/Olyx-labs/olyx-guardrails/blob/master/examples/ruby_only.rb) and
[API reference](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/API.md) for the full flow and result contracts.

## Add Rails enforcement

Generate an initializer and environment-keyed policy file:

```sh
bin/rails generate olyx_guardrails:install
```

Review `config/initializers/olyx_guardrails.rb` and
`config/olyx_guardrails.yml`, then include an adapter at an application boundary:

```ruby
class AiRequestsController < ApplicationController
  include Olyx::Guardrails::Rails::Controller

  rescue_from Olyx::Guardrails::Blocked do |error|
    render json: { error: "input_rejected", decision: error.decision },
           status: :unprocessable_entity
  end

  def create
    prompt = params.require(:prompt)
    guardrails_check!(prompt)
    safe_prompt = guardrails_redact(prompt)[:text]

    completion = LlmClient.complete(safe_prompt)
    Olyx::Guardrails::Rails::Enforcer.check_output!(completion)
    safe_output = Olyx::Guardrails::Rails.redact_output(completion)[:text]

    render json: { completion: safe_output }
  end
end
```

`LlmClient` represents your application's existing model client. This controller
example belongs in a Rails application; it is not a standalone script.

Enforcement is opt-in. The gem does not automatically scan every request, job,
upload, or model call. The [Rails guide](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/RAILS.md) covers controllers,
Active Job, Active Model, GraphQL, Action Cable, extracted upload text,
instrumentation, and notifications.

## Defaults and operational behavior

The default policy:

- rejects input longer than 10,000 Ruby characters;
- blocks detected prompt injection;
- reports PII and secrets without blocking them;
- defines no custom restricted-content rules; and
- preserves the deterministic decision if an optional LLM provider fails.

Define an explicit production policy. If semantic analysis is required, choose
`llm_failure_mode: :block` or `:raise`. The application supplies the classifier
callable and owns its authentication, transport, timeouts, and retries.
Semantic findings can add violations but cannot clear deterministic findings.
See [policies](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/POLICIES.md) and the
[provider contract](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/API.md#llm-provider-contract).

Rails can publish content-free Active Support events. Optional notifier handlers
receive sanitized events and run synchronously unless your application queues
delivery. See [operations](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/OPERATIONS.md) for data handling and failure modes.

## Limitations

Pattern-based checks can miss novel attacks, paraphrasing, translations,
unsupported formats, and nested encodings. PII coverage is strongest for the
documented North American and common international formats. Secret detection
is format-based. Restricted-content rules do not infer semantic equivalents
unless your application supplies additional analysis.

Completed-output methods evaluate complete values; they do not enforce a policy
on tokens already streamed to a caller. Model routing, tool permissions,
authorization, file extraction, distributed quotas, and audit storage remain
application responsibilities.

Treat guardrails as one layer of application protection. Read the
[detection limits](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/OPERATIONS.md#detection-limits) before enabling production
blocking.

## Documentation and examples

- [Documentation index](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/README.md)
- [Policies and restricted content](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/POLICIES.md)
- [Rails integration](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/RAILS.md)
- [Operations and notifications](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/OPERATIONS.md)
- [Ruby API reference](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/API.md)
- [Runnable Ruby example](https://github.com/Olyx-labs/olyx-guardrails/blob/master/examples/ruby_only.rb)
- [Custom policies](https://github.com/Olyx-labs/olyx-guardrails/blob/master/examples/custom_policy.rb)
- [Application-owned local classifier](https://github.com/Olyx-labs/olyx-guardrails/blob/master/examples/local_llm_provider.rb)
- [Notifier handlers](https://github.com/Olyx-labs/olyx-guardrails/blob/master/examples/notifier.rb)

## Contributing and security

See [CONTRIBUTING.md](https://github.com/Olyx-labs/olyx-guardrails/blob/master/CONTRIBUTING.md) for development setup and checks,
[CHANGELOG.md](CHANGELOG.md) for release changes, and the
[release runbook](https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/RELEASING.md) for maintainer procedures.

Rails adapter changes must also pass `bundle exec appraisal rake test`.

Report vulnerabilities through the [security policy](https://github.com/Olyx-labs/olyx-guardrails/blob/master/SECURITY.md).

## License

[Apache License 2.0](LICENSE).
