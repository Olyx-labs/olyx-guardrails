# frozen_string_literal: true

# Run with:
#   ruby -Ilib examples/ruby_only.rb "Summarize these release notes"
#
# This path has no Rails dependency and keeps policy, enforcement, model calls,
# and notification delivery under the application's control.

require 'olyx/guardrails'

policy = Olyx::Guardrails::Policy.new(
  name: 'ruby-application',
  max_input_length: 4_000,
  block_pii: true,
  block_injections: true,
  block_secrets: true,
  ai_failure_mode: :block,
  secret_patterns: ['company-token-[a-z0-9]{24}'],
  rules: [
    {
      name: :confidential_project,
      terms: ['Project Falcon'],
      match: :whole_word,
      replacement: '[CONFIDENTIAL_PROJECT]'
    }
  ]
)

notifier = Olyx::Guardrails::Notifier.new(
  policy: policy,
  handlers: { stderr: ->(event) { warn("guardrail event: #{event.inspect}") } }
)

prompt = ARGV.fetch(0, 'Summarize these public release notes')
decision = Olyx::Guardrails.check(prompt, policy: policy)
notifier.notify(decision, input: prompt, metadata: { boundary: 'model_input' })
unless decision[:allowed]
  rejected = decision[:checks].reject { |check| check[:allowed] }
  rejected_types = rejected.map { |check| check[:type] }
  abort "Input rejected: #{rejected_types.join(', ')}"
end

safe_prompt = Olyx::Guardrails.redact(prompt, policy: policy)[:text]

# Replace this lambda with the application's model client.
model = ->(input) { "Completed response for: #{input}" }
completion = model.call(safe_prompt)

output_decision = Olyx::Guardrails.check_output(completion, policy: policy)
notifier.notify(output_decision, input: completion, metadata: { boundary: 'model_output' })
abort 'Output rejected' unless output_decision[:allowed]

puts Olyx::Guardrails.redact_output(completion, policy: policy)[:text]
