# frozen_string_literal: true

require_relative 'lib/olyx/guardrails/version'

internal_rdoc_pattern = 'lib/olyx/guardrails/(?=.*\.rb$)(?!' \
                        '(?:version|errors|policy|policy_rule|pii_scrubber|injection_detector|' \
                        'secret_scanner|notifier|rails|railtie)\.rb$|' \
                        'rails/(?:configuration|enforcer|controller|graphql|action_cable|job|' \
                        'active_job_handler|active_model_validator|upload)\.rb$)'

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

  s.files         = Dir['lib/**/*.rb'] + Dir['lib/generators/**/*'].select { |path| File.file?(path) } +
                    Dir['examples/*.rb'] + Dir['docs/*.md'] +
                    %w[LICENSE README.md CHANGELOG.md SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md]
  s.require_paths = ['lib']
  s.extra_rdoc_files = ['README.md', 'CHANGELOG.md'] + Dir['docs/*.md']
  s.rdoc_options = [
    '--main', 'README.md',
    '--exclude', 'lib/generators/',
    '--exclude', internal_rdoc_pattern
  ]

  s.required_ruby_version = '>= 3.4'

  s.add_dependency 'base64', '>= 0.2', '< 1'
end
