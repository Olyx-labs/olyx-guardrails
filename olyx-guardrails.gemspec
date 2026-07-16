Gem::Specification.new do |s|
  s.name        = "olyx-guardrails"
  s.version     = "0.1.0"
  s.summary     = "AI guardrails for Ruby: PII scrubbing, prompt injection detection, and secret scanning."
  s.description = "Standalone Ruby library for AI input/output safety. Detects and redacts PII, " \
                  "identifies prompt injection attacks, and scans for leaked secrets — " \
                  "no external dependencies, no API calls, runs entirely in-process."
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

  s.files         = Dir["lib/**/*.rb"] + %w[LICENSE README.md CHANGELOG.md]
  s.require_paths = ["lib"]

  s.required_ruby_version = ">= 3.1"

  s.add_development_dependency "minitest", "~> 5.0"
  s.add_development_dependency "rake",     "~> 13.0"
end
