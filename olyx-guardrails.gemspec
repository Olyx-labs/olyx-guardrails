Gem::Specification.new do |s|
  s.name        = "olyx-guardrails"
  s.version     = "2026.7.14"
  s.summary     = "Open-source AI guardrails: PII scrubbing, prompt injection detection, and secret scanning."
  s.description = "Standalone Ruby library providing the core Olyx safety pipeline. " \
                  "Enterprise users get the same primitives accelerated by the Rust olyx-core binary."
  s.license     = "Apache-2.0"
  s.authors     = ["Olyx Labs"]
  s.email       = ["hello@olyxai.io"]
  s.homepage    = "https://github.com/olyx-labs/olyx-guardrails"

  s.files         = Dir["lib/**/*.rb"]
  s.require_paths = ["lib"]

  s.required_ruby_version = ">= 3.1"
end
