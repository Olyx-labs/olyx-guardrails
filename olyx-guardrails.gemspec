# frozen_string_literal: true

require_relative "lib/olyx/guardrails/version"

Gem::Specification.new do |s|
  s.name        = "olyx-guardrails"
  s.version     = Olyx::Guardrails::VERSION
  s.summary     = "AI governance guardrails for Ruby: PII scrubbing, injection detection, secret scanning, and Rootly incident integration."
  s.description = "Standalone Ruby library for AI input safety. Detects and redacts PII, " \
                  "identifies prompt injection attacks (including multi-turn patterns), scans for " \
                  "leaked secrets, and opens Rootly incidents on violations — no external " \
                  "dependencies for the core checks, runs entirely in-process. Ships with a " \
                  "pluggable ai_analyzer: hook for LLM-backed semantic evaluation."
  s.license     = "Apache-2.0"
  s.authors     = ["Moses Njoroge"]
  s.email       = ["mosesnjoroge@olyxai.io"]
  s.homepage    = "https://github.com/mosesnjoroge/olyx-guardrails"
  s.metadata    = {
    "source_code_uri"        => "https://github.com/mosesnjoroge/olyx-guardrails",
    "changelog_uri"          => "https://github.com/mosesnjoroge/olyx-guardrails/blob/master/CHANGELOG.md",
    "documentation_uri"      => "https://github.com/mosesnjoroge/olyx-guardrails/blob/master/docs/API.md",
    "bug_tracker_uri"        => "https://github.com/mosesnjoroge/olyx-guardrails/issues",
    "allowed_push_host"      => "https://rubygems.org",
    "rubygems_mfa_required"  => "true"
  }

  s.files         = Dir["lib/**/*.rb"] + Dir["examples/*.rb"] + Dir["docs/*.md"] +
                    %w[LICENSE README.md CHANGELOG.md SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md]
  s.require_paths = ["lib"]

  s.required_ruby_version = ">= 3.4"

  s.add_development_dependency "minitest", "~> 5.0"
  s.add_development_dependency "rake",     "~> 13.0"
  s.add_development_dependency "rubycritic", "~> 5.0"
end
