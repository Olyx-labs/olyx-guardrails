# frozen_string_literal: true

require_relative 'lib/olyx/guardrails/version'

internal_rdoc_pattern = 'lib/olyx/guardrails/(?=.*\.rb$)(?!' \
                        '(?:version|errors|policy|policy_rule|pii_scrubber|injection_detector|' \
                        'secret_scanner|notifier|rails|railtie)\.rb$|' \
                        'rails/(?:configuration|enforcer|controller|graphql|action_cable|job|' \
                        'active_job_handler|active_model_validator|upload)\.rb$)'

consumer_documentation = %w[
  docs/API.md
  docs/OPERATIONS.md
  docs/POLICIES.md
  docs/RAILS.md
  docs/README.md
].freeze
consumer_examples = %w[
  examples/custom_policy.rb
  examples/local_llm_provider.rb
  examples/notifier.rb
  examples/rails_opt_in.rb
  examples/ruby_only.rb
].freeze
generator_templates = Dir['lib/generators/**/*.tt'].freeze
runtime_files = Dir['lib/**/*.rb'].freeze

Gem::Specification.new do |s|
  s.name        = 'olyx-guardrails'
  s.version     = Olyx::Guardrails::VERSION
  s.summary     = 'In-process AI guardrails for Ruby and Rails with configurable policies.'
  s.description = 'Standalone Ruby library for completed AI input and output safety. Detects and redacts PII, ' \
                  'identifies prompt injection attacks (including multi-turn patterns), scans for ' \
                  'leaked secrets, enforces reusable custom restricted-content policies, and ' \
                  'provides explicit Rails boundary adapters and sanitized application-defined notifications — ' \
                  'runs entirely in-process with one lightweight bundled-gem dependency. ' \
                  'Ships with a provider-agnostic llm_provider: hook ' \
                  'for LLM-backed semantic evaluation.'
  s.license     = 'Apache-2.0'
  s.authors     = ['Moses Njoroge']
  s.email       = ['mosesnjoroge@olyxai.io']
  s.homepage    = 'https://github.com/Olyx-labs/olyx-guardrails'
  s.metadata    = {
    'source_code_uri' => 'https://github.com/Olyx-labs/olyx-guardrails',
    'changelog_uri' => 'https://github.com/Olyx-labs/olyx-guardrails/blob/master/CHANGELOG.md',
    'documentation_uri' => 'https://github.com/Olyx-labs/olyx-guardrails/blob/master/docs/README.md',
    'bug_tracker_uri' => 'https://github.com/Olyx-labs/olyx-guardrails/issues',
    'allowed_push_host' => 'https://rubygems.org',
    'rubygems_mfa_required' => 'true'
  }

  s.files = (
    runtime_files +
    generator_templates +
    consumer_examples +
    consumer_documentation +
    %w[CHANGELOG.md LICENSE README.md]
  ).sort
  s.require_paths = ['lib']
  s.extra_rdoc_files = %w[CHANGELOG.md README.md] + consumer_documentation
  s.rdoc_options = [
    '--main', 'README.md',
    '--exclude', 'lib/generators/',
    '--exclude', internal_rdoc_pattern
  ]

  s.required_ruby_version = '>= 3.4'

  s.add_dependency 'base64', '>= 0.2', '< 1'
end
