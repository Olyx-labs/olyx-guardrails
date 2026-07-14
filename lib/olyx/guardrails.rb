require_relative "guardrails/version"
require_relative "guardrails/pii_scrubber"
require_relative "guardrails/injection_detector"
require_relative "guardrails/secret_scanner"

module Olyx
  module Guardrails
    # Single-call guardrail check — runs PII detection, injection detection,
    # and secret scanning. Returns the same shape as GuardrailService.ruby_check
    # so olyx-api can delegate directly.
    #
    #   Olyx::Guardrails.check(
    #     input,
    #     max_input_length:    10_000,
    #     injection_block:     true,
    #     secret_action:       "alert",
    #     custom_patterns:     []
    #   )
    def self.check(
      input,
      max_input_length: 10_000,
      injection_block: true,
      secret_action: "alert",
      custom_patterns: []
    )
      input_str = input.to_s
      checks    = []

      # PII
      pii_redacted  = PiiScrubber.scrub(input_str)
      pii_detected  = pii_redacted != input_str
      checks << { type: "pii", allowed: true, detected: pii_detected }

      # Injection
      injection_result = InjectionDetector.scan([ { "role" => "user", "content" => input_str } ])
      injection_attempt = injection_result[:injection_attempt]
      checks << {
        type:             "injection",
        allowed:          !injection_attempt || !injection_block,
        injection_attempt: injection_attempt,
        patterns:         injection_result[:patterns]
      }

      # Secret scanning — rescue Blocked so check() always returns a result hash.
      # Callers that want the exception (proxy controllers) call SecretScanner.scan directly.
      secret_result = begin
        SecretScanner.scan(input_str, secret_action: secret_action, custom_patterns: custom_patterns)
      rescue SecretScanner::Blocked => e
        { text: input_str, leaked: true, findings: e.findings }
      end
      secret_leaked = secret_result[:leaked]
      secret_blocks = secret_action == "block"
      checks << {
        type:    "secret",
        allowed: !secret_leaked || !secret_blocks,
        leaked:  secret_leaked,
        count:   secret_result[:findings].size
      }

      # Length
      length_exceeded = input_str.length > max_input_length
      checks << {
        type:       "length",
        allowed:    !length_exceeded,
        length:     input_str.length,
        max_length: max_input_length
      }

      blocked = !checks.all? { |c| c[:allowed] }

      {
        allowed:           !blocked,
        pii_detected:      pii_detected,
        injection_attempt: injection_attempt,
        secret_leaked:     secret_leaked,
        risk_score:        compute_risk_score(pii: pii_detected, injection: injection_attempt, secret: secret_leaked, checks: checks),
        checks:            checks
      }
    end

    def self.compute_risk_score(pii:, injection:, secret:, checks:)
      score  = 0.0
      score += 0.5  if injection
      score += 0.25 if secret
      score += 0.10 if pii
      score += 0.15 if checks.any? { |c| !c[:allowed] }
      score.clamp(0.0, 1.0).round(4)
    end
    private_class_method :compute_risk_score
  end
end
