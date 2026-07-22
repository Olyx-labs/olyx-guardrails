# frozen_string_literal: true

require_relative 'lib/olyx/guardrails/version'

Gem::Specification.new do |s|
  s.name        = 'olyx-guardrails'
  s.version     = Olyx::Guardrails::VERSION
  s.summary     = 'In-process AI guardrails for Ruby and Rails with configurable policies.'
  s.description = 'Standalone Ruby library for completed AI input and output safety. Detects and redacts PII, ' \
                  'identifies prompt injection attacks (including multi-turn patterns), scans for ' \
                  'leaked secrets, enforces reusable custom restricted-content policies, and ' \
                  'provides explicit Rails boundary adapters and sanitized application-defined notifications — ' \
                  'no external dependencies for the core checks, runs entirely in-process. ' \
                  'Ships with a pluggable ai_analyzer: hook ' \
                  'for LLM-backed semantic evaluation.'
  s.license     = 'Apache-2.0'
  s.authors     = ['Moses Njoroge']
  s.email       = ['mosesnjoroge@olyxai.io']
  s.homepage    = 'https://github.com/mosesnjoroge/olyx-guardrails'
  s.metadata    = {
    'source_code_uri' => 'https://github.com/mosesnjoroge/olyx-guardrails',
    'changelog_uri' => 'https://github.com/mosesnjoroge/olyx-guardrails/blob/master/CHANGELOG.md',
    'documentation_uri' => 'https://github.com/mosesnjoroge/olyx-guardrails/blob/master/docs/API.md',
    'bug_tracker_uri' => 'https://github.com/mosesnjoroge/olyx-guardrails/issues',
    'allowed_push_host' => 'https://rubygems.org',
    'rubygems_mfa_required' => 'true'
  }

  s.files         = Dir['lib/**/*.rb'] + Dir['lib/generators/**/*'].select { |path| File.file?(path) } +
                    Dir['examples/*.rb'] + Dir['docs/*.md'] +
                    %w[LICENSE README.md CHANGELOG.md SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md]
  s.require_paths = ['lib']

  s.required_ruby_version = '>= 3.4'
end
