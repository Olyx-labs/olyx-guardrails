# frozen_string_literal: true

# Demonstrates one reusable policy for built-in checks, custom credential
# formats, and organization-specific restricted content.

require 'olyx/guardrails'

POLICY = Olyx::Guardrails::Policy.new(
  name: 'production',
  max_input_length: 4_000,
  block_pii: true,
  block_injections: true,
  block_secrets: true,
  ai_failure_mode: :block,
  secret_patterns: ['company-token-[a-z0-9]{24}'],
  rules: [
    {
      name: :confidential_projects,
      description: 'Internal project names',
      patterns: ['project[ -]falcon', /PF-\d{4}/],
      block: true,
      replacement: '[CONFIDENTIAL_PROJECT]'
    },
    {
      name: :competitor_references,
      terms: ['competitor corp'],
      match: :whole_word,
      block: false
    }
  ]
)

input = ARGV[0] || 'Compare Project Falcon with Competitor Corp'
decision = Olyx::Guardrails.check(input, policy: POLICY)
redaction = Olyx::Guardrails.redact(input, policy: POLICY)

puts "Policy:     #{decision[:policy_name]}"
puts "Allowed:    #{decision[:allowed]}"
puts "Violated:   #{decision[:policy_violated]}"
puts "Rules:      #{decision[:policy_findings].map { |finding| finding[:rule] }.uniq.join(', ')}"
puts "Safe text:  #{redaction[:text]}"
