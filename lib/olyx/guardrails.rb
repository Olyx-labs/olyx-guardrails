require_relative "guardrails/version"
require_relative "guardrails/pii_scrubber"
require_relative "guardrails/injection_detector"
require_relative "guardrails/secret_scanner"

module Olyx
  module Guardrails
    INJECTION_RISK_WEIGHT = 0.50
    SECRET_RISK_WEIGHT    = 0.25
    PII_RISK_WEIGHT       = 0.10
    BLOCKED_RISK_WEIGHT   = 0.15

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

      pii_check       = check_pii(input_str)
      injection_check = check_injection(input_str, injection_block)
      secret_check    = check_secret(input_str, secret_action, custom_patterns)
      length_check    = check_length(input_str, max_input_length)
      checks          = [pii_check, injection_check, secret_check, length_check]

      {
        allowed:           checks.all? { |c| c[:allowed] },
        pii_detected:      pii_check[:detected],
        injection_attempt: injection_check[:injection_attempt],
        secret_leaked:     secret_check[:leaked],
        risk_score:        compute_risk_score(
          pii:       pii_check[:detected],
          injection: injection_check[:injection_attempt],
          secret:    secret_check[:leaked],
          checks:    checks
        ),
        checks: checks
      }
    end

    private_class_method def self.check_pii(input_str)
      detected = PiiScrubber.scrub(input_str) != input_str
      # PII alone never blocks a request — it only feeds risk_score.
      { type: "pii", allowed: true, detected: detected }
    end

    private_class_method def self.check_injection(input_str, injection_block)
      result  = InjectionDetector.scan([ { "role" => "user", "content" => input_str } ])
      attempt = result[:injection_attempt]
      {
        type:              "injection",
        allowed:           !attempt || !injection_block,
        injection_attempt: attempt,
        patterns:          result[:patterns]
      }
    end

    # Rescues Blocked so check() always returns a result hash. Callers that
    # want the exception (proxy controllers) call SecretScanner.scan directly.
    private_class_method def self.check_secret(input_str, secret_action, custom_patterns)
      result = begin
        SecretScanner.scan(input_str, secret_action: secret_action, custom_patterns: custom_patterns)
      rescue SecretScanner::Blocked => e
        { text: input_str, leaked: true, findings: e.findings }
      end

      leaked = result[:leaked]
      blocks = secret_action == "block"
      { type: "secret", allowed: !leaked || !blocks, leaked: leaked, count: result[:findings].size }
    end

    private_class_method def self.check_length(input_str, max_input_length)
      exceeded = input_str.length > max_input_length
      { type: "length", allowed: !exceeded, length: input_str.length, max_length: max_input_length }
    end

    private_class_method def self.compute_risk_score(pii:, injection:, secret:, checks:)
      score  = 0.0
      score += INJECTION_RISK_WEIGHT if injection
      score += SECRET_RISK_WEIGHT    if secret
      score += PII_RISK_WEIGHT       if pii
      score += BLOCKED_RISK_WEIGHT   if checks.any? { |c| !c[:allowed] }
      score.clamp(0.0, 1.0).round(4)
    end
  end
end
