# frozen_string_literal: true

# Demonstrates one reusable policy for built-in checks, custom credential
# formats, and organization-specific restricted content.

require 'olyx/guardrails'

# Policies are immutable after construction and can be reused across requests.
POLICY = Olyx::Guardrails::Policy.new(
  name: 'production',
  max_input_length: 4_000,
  block_pii: true,
  block_injections: true,
  block_secrets: true,
  # This setting matters only when an llm_provider is passed to a check.
  llm_failure_mode: :block,
  # Custom secret patterns are regular-expression source strings.
  secret_patterns: ['company-token-[a-z0-9]{24}'],
  rules: [
    # Pattern rules accept regex source strings or Regexp objects.
    {
      name: :confidential_projects,
      description: 'Internal project names',
      patterns: ['project[ -]falcon', /PF-\d{4}/],
      block: true,
      replacement: '[CONFIDENTIAL_PROJECT]'
    },
    # Monitoring-only rules report findings without rejecting the decision.
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

# Checking and redaction are deliberately separate: one decides, one transforms.
puts "Policy:     #{decision[:policy_name]}"
puts "Allowed:    #{decision[:allowed]}"
puts "Violated:   #{decision[:policy_violated]}"
puts "Rules:      #{decision[:policy_findings].map { |finding| finding[:rule] }.uniq.join(', ')}"
puts "Safe text:  #{redaction[:text]}"
