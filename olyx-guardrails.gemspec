Gem::Specification.new do |s|
  s.name        = "olyx-guardrails"
  s.version     = "0.2.0"
  s.summary     = "AI governance guardrails for Ruby: PII scrubbing, injection detection, secret scanning, and Rootly incident integration."
  s.description = "Standalone Ruby library for AI input safety. Detects and redacts PII, " \
                  "identifies prompt injection attacks (including multi-turn patterns), scans for " \
                  "leaked secrets, and opens Rootly incidents on violations — no external " \
                  "dependencies for the core checks, runs entirely in-process. Ships with a " \
                  "pluggable ai_analyzer: hook for LLM-backed semantic evaluation."
  s.license     = "Apache-2.0"
  s.authors     = ["Moses Njoroge"]
  s.email       = ["mosesnjoroge@olyxai.io"]
  s.homepage    = "https://github.com/olyx-labs/olyx-guardrails"
  s.metadata    = {
    "source_code_uri"        => "https://github.com/olyx-labs/olyx-guardrails",
    "changelog_uri"          => "https://github.com/olyx-labs/olyx-guardrails/blob/main/CHANGELOG.md",
    "bug_tracker_uri"        => "https://github.com/olyx-labs/olyx-guardrails/issues",
    "rubygems_mfa_required"  => "true"
  }

  s.files         = Dir["lib/**/*.rb"] + Dir["examples/*.rb"] + %w[LICENSE README.md CHANGELOG.md]
  s.require_paths = ["lib"]

  s.required_ruby_version = ">= 3.1"

  s.add_development_dependency "minitest", "~> 5.0"
  s.add_development_dependency "rake",     "~> 13.0"
end
