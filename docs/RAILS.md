# Rails Integration

This guide explains the opt-in Rails integration supplied by Olyx Guardrails.

After reading this guide, the reader will know:

- how the Railtie loads and finalizes configuration;
- how to protect each supported Rails boundary;
- which exceptions and return values to expect;
- how instrumentation and notifications avoid content leakage; and
- which responsibilities remain with the application.

## Supported versions

The Rails integration is tested against Rails 8.0 and 8.1 on Ruby 3.4.
The framework-free API remains available without loading Rails.

Only the listed Rails series are supported. Framework support follows upstream
Rails security support: after a Rails series reaches end-of-life, a subsequent
gem release may remove it rather than backporting framework security fixes.
Support changes are recorded in the project changelog.

## Installation

Add the gem to the Rails application:

```ruby
gem "olyx-guardrails", "~> 1.1"
```

Run the install generator:

```bash
bin/rails generate olyx_guardrails:install
```

The generator creates:

- `config/initializers/olyx_guardrails.rb`; and
- `config/olyx_guardrails.yml`.

The Railtie adds configured parameter names to
`config.filter_parameters` after application initializers load. It finalizes
and freezes guardrail configuration in `after_initialize`.

## Configuration

The generated initializer uses a policy file:

```ruby
Olyx::Guardrails::Rails.configure(
  enabled: true,
  policy_path: Rails.root.join("config/olyx_guardrails.yml"),
  llm_provider: nil,
  notifier_handlers: {},
  filter_parameters: %i[prompt system_prompt llm_input]
)
```

Configuration accepts:

| Option | Default | Contract |
|---|---:|---|
| `enabled` | `true` | Literal Boolean |
| `policy` | `nil` | An `Olyx::Guardrails::Policy` |
| `policy_path` | `nil` | Path to direct or environment-keyed YAML |
| `llm_provider` | `nil` | Callable object or `nil` |
| `notifier_handlers` | `{}` | Named callable handlers |
| `filter_parameters` | common AI input names | Array of Strings or Symbols |

Configure either `policy` or `policy_path`, never both. When both are `nil`,
the integration uses `Policy.default`.

Configuration becomes immutable after Rails initialization. A later call to
`Rails.configure` raises `Olyx::Guardrails::ConfigurationError`.

When `enabled` is `false`, calling the Rails facade raises
`ConfigurationError`. Disabled integration never silently permits input.

## Policy files

The generated policy file contains an entry for each Rails environment:

```yaml
development:
  name: development
  max_input_length: 10000
  block_pii: false
  block_injections: true
  block_secrets: false
  llm_failure_mode: allow
  secret_patterns: []
  rules: []

production:
  name: production
  max_input_length: 4000
  block_pii: true
  block_injections: true
  block_secrets: true
  llm_failure_mode: block
  secret_patterns: []
  rules: []
```

The loader uses `YAML.safe_load_file`. It does not evaluate ERB, aliases,
symbols, or arbitrary Ruby classes. It accepts either an environment-keyed
document or one direct policy hash.

Missing files, unreadable files, malformed YAML, unsafe YAML, missing
environment sections, and invalid policy values raise
`Olyx::Guardrails::ConfigurationError` during initialization.

See the [Policies guide](POLICIES.md) for the full YAML rule language.

## Rails facade

The configured facade returns the same result hashes as the core API:

```ruby
Olyx::Guardrails::Rails.check(input, metadata: {})
Olyx::Guardrails::Rails.check_messages(messages, metadata: {})
Olyx::Guardrails::Rails.check_output(output, metadata: {})
Olyx::Guardrails::Rails.redact(input)
Olyx::Guardrails::Rails.redact_output(output)
```

Decision methods run the configured policy and LLM provider, publish
content-free Active Support events, and invoke the configured notifier when
risk is greater than zero. Redaction methods publish a redaction event.
Every `metadata:` argument must be a Hash; invalid metadata raises
`ArgumentError` consistently across the facade, enforcer, controller, GraphQL,
Action Cable, and upload adapters.

## Controller boundaries

Include the controller concern in controllers that accept AI-bound input:

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
    guardrails_check!(prompt, metadata: { account_id: current_account.id })

    safe_prompt = guardrails_redact(prompt)[:text]
    completion = LlmClient.complete(safe_prompt)
    Olyx::Guardrails::Rails::Enforcer.check_output!(completion)

    render json: { completion: completion }, status: :created
  end
end
```

The concern adds private helpers:

| Helper | Behavior |
|---|---|
| `guardrails_check(input, metadata: {})` | Returns a decision |
| `guardrails_check!(input, metadata: {})` | Returns a decision or raises `Blocked` |
| `guardrails_redact(input)` | Returns a redaction result |

Controller metadata automatically includes `request_id`, `controller`,
`action`, and `http_method`. Explicit metadata merges on top of these values.
Metadata must be a Hash.

The application chooses the HTTP status and response body. A rejection may be a
validation error, authorization decision, or policy violation depending on the
endpoint.

## Reusable enforcement

Use `Rails::Enforcer` from service objects, callbacks, custom transports, and
other application-owned boundaries:

```ruby
Olyx::Guardrails::Rails::Enforcer.check!(input, metadata: {})
Olyx::Guardrails::Rails::Enforcer.check_messages!(messages, metadata: {})
Olyx::Guardrails::Rails::Enforcer.check_output!(output, metadata: {})
```

Each method returns the decision when `allowed` is true. Otherwise it raises
`Olyx::Guardrails::Blocked`.

The exception contains a deeply frozen, content-free `decision`:

```ruby
{
  policy_name: "production",
  allowed: false,
  risk_score: 0.75,
  violations: ["restricted_content"],
  policy_rules: ["confidential_projects"]
}
```

The summary never contains raw input, redacted output, matched text, metadata,
or LLM reasoning.

## GraphQL

Include the GraphQL concern in a resolver or mutation:

```ruby
class CompletionResolver
  include Olyx::Guardrails::Rails::GraphQL

  def resolve(prompt:)
    guardrails_check_graphql!(prompt)
    completion = LlmClient.complete(prompt)
    guardrails_check_graphql_output!(completion)
    { completion: completion }
  end
end
```

The helpers are private and accept `metadata: {}`:

- `guardrails_check_graphql!`
- `guardrails_check_graphql_output!`

They add the resolver class name under `graphql_resolver`.

## Action Cable

Include the Action Cable concern in channels that receive or transmit AI-bound
content:

```ruby
class PromptChannel < ApplicationCable::Channel
  include Olyx::Guardrails::Rails::ActionCable

  def receive(data)
    guardrails_check_cable!(data.fetch("prompt"))
    transmit(status: "accepted")
  end
end
```

The private helpers are:

- `guardrails_check_cable!`
- `guardrails_check_cable_output!`

They accept `metadata: {}` and add the channel class name under `channel`.

## Active Job arguments

The Active Job concern checks explicitly declared arguments immediately before
`perform`:

```ruby
class CompletionJob < ApplicationJob
  include Olyx::Guardrails::Rails::Job

  guardrails_input_arguments 0, :system_prompt

  def perform(prompt, system_prompt:)
    LlmClient.complete(prompt, system_prompt: system_prompt)
  end
end
```

Integer selectors address positional arguments. Symbol selectors find the
keyword Hash and accept either Symbol or String keys.

The declaration requires at least one non-negative Integer or Symbol and
validates selector types immediately. Missing indexes and missing keywords
raise `ArgumentError` when the job runs. Declarations are inherited by job
subclasses. A rejected value raises `Olyx::Guardrails::Blocked` before job work
begins.

This concern does not inspect arguments that were not declared.

## Active Model validation

Use the validator for explicitly declared AI-bound attributes:

```ruby
class PromptDraft
  include ActiveModel::Model

  attr_accessor :prompt

  validates :prompt, olyx_guardrails: true
end
```

The default error is `was rejected by guardrail policy`. Override it with the
normal Active Model `message:` option:

```ruby
validates :prompt,
  olyx_guardrails: { message: "contains restricted content" }
```

By default, validation uses the finalized Rails configuration. Pass a core
policy to bypass the Rails facade for that attribute:

```ruby
validates :prompt, olyx_guardrails: { policy: PROMPT_POLICY }
```

## Uploads

The application owns file type validation, size limits, malware scanning,
storage, and text extraction. The upload adapter only evaluates returned text:

```ruby
result = Olyx::Guardrails::Rails::Upload.check(
  params.require(:document),
  extractor: ->(upload) { DocumentText.extract(upload.tempfile) },
  metadata: { source: "document_upload" }
)
```

`Upload.check!` raises `Blocked` when rejected. The extractor must respond to
`call` and return a String; otherwise the adapter raises `ArgumentError`.

Set extraction limits before returning text. The policy length check limits
evaluation but does not prevent an extractor from reading an unbounded file.

## Notifications with Active Job

Any Rails notification handler can perform synchronous work. Use
`ActiveJobHandler` when delivery should be queued:

```ruby
Olyx::Guardrails::Rails.configure(
  policy_path: Rails.root.join("config/olyx_guardrails.yml"),
  notifier_handlers: {
    incidents: Olyx::Guardrails::Rails::ActiveJobHandler.new(
      job: "GuardrailIncidentJob",
      queue: :incidents
    )
  }
)
```

`job:` accepts an Active Job class or a reload-safe String/Symbol constant
name. String and Symbol names resolve at delivery time, which supports Rails
code reloading. The target must respond to `perform_later`.

`queue:` accepts a non-empty String or Symbol. It is optional.

The job receives the immutable, sanitized event described in the
[Operations guide](OPERATIONS.md#notification-event).

## Active Support instrumentation

Subscribe with the standard Active Support API:

```ruby
ActiveSupport::Notifications.subscribe("violation.olyx_guardrails") do |event|
  Rails.logger.warn(event.payload.to_json)
end
```

Published events are:

| Event | When published |
|---|---|
| `check.olyx_guardrails` | After every Rails decision |
| `violation.olyx_guardrails` | When decision risk is greater than zero |
| `redact.olyx_guardrails` | After every Rails redaction |
| `notification.olyx_guardrails` | After notifier delivery |

### Check and violation payload

```ruby
{
  policy_name: String,
  allowed: Boolean,
  risk_score: Float,
  violations: Array<String>,
  policy_rules: Array<String>,
  evaluation_duration_ms: Float
}
```

### Redaction payload

```ruby
{
  policy_name: String,
  redacted: Boolean,
  pii_detected: Boolean,
  secret_leaked: Boolean,
  policy_violated: Boolean,
  evaluation_duration_ms: Float
}
```

### Notification payload

```ruby
{
  success: Boolean,
  delivery_count: Integer
}
```

Payloads do not contain raw input, redacted output, metadata, findings, matched
text, notification previews, handler errors, or LLM reasoning. Subscriber
exceptions are isolated and cannot change an enforcement result.

## Reloading and initialization

The Railtie intentionally separates configuration from runtime evaluation:

1. application initializers call `Rails.configure`;
2. parameter filters are added after config initializers load;
3. `after_initialize` safely loads the policy and builds the notifier; and
4. the configuration object freezes before requests are served.

Application code should not mutate guardrail configuration during a request.
Use environment-specific YAML and restart the application to deploy policy
changes.

## Boundaries not covered automatically

The Rails adapter does not automatically:

- identify which application fields are AI-bound;
- intercept arbitrary model client calls;
- parse uploads;
- add model callbacks;
- scan undeclared job arguments;
- inspect streaming tokens;
- enforce distributed rate limits; or
- centralize policy or audit state across processes.

Place an explicit adapter at every ingestion and completed-output boundary.
The [Operations guide](OPERATIONS.md) covers distributed and streaming
limitations in more detail.
