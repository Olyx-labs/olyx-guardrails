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
    # ai_analyzer: optional callable — receives (text, context) and returns a hash.
    #
    # context keys passed to the hook:
    #   pii_detected:       Boolean — regex found PII
    #   injection_attempt:  Boolean — regex found injection patterns
    #   injection_patterns: Array   — matched pattern details
    #   secret_leaked:      Boolean — regex found secrets
    #
    # Expected return keys (all optional):
    #   injection_attempt: Boolean
    #   pii_detected:      Boolean
    #   secret_leaked:     Boolean
    #   risk_score:        Float (0.0..1.0) — takes precedence when higher than regex score
    #   reason:            String — LLM explanation, included in ai_analysis
    #
    # The hook follows defense-in-depth: AI findings union with regex findings —
    # the hook can flag additional violations but cannot clear existing ones.
    # Exceptions raised by the hook are rescued; the error is recorded in
    # ai_analysis[:error] and the regex result stands.
    def self.check(
      input,
      max_input_length: 10_000,
      injection_block: true,
      secret_action: "alert",
      custom_patterns: [],
      ai_analyzer: nil
    )
      input_str    = input.to_s
      length_check = check_length(input_str, max_input_length)

      if length_check[:allowed]
        pii_check       = check_pii(input_str)
        injection_check = check_injection(input_str, injection_block)
        secret_check    = check_secret(input_str, secret_action, custom_patterns)
      else
        # Input already exceeds max_input_length — skip the expensive scans
        # rather than paying their full cost on content that's being
        # rejected on size alone. Callers who need to inspect an oversized,
        # rejected payload can call PiiScrubber/InjectionDetector/
        # SecretScanner directly.
        pii_check       = skipped_check("pii", detected: false)
        injection_check = skipped_check("injection", injection_attempt: false, patterns: [])
        secret_check    = skipped_check("secret", leaked: false, count: 0)
      end

      ai_result = if ai_analyzer && length_check[:allowed]
        run_ai_analysis(ai_analyzer, input_str, {
          pii_detected:       pii_check[:detected],
          injection_attempt:  injection_check[:injection_attempt],
          injection_patterns: injection_check[:patterns],
          secret_leaked:      secret_check[:leaked]
        })
      end

      if ai_result && !ai_result[:error]
        injection_check = ai_merge_injection(injection_check, ai_result, injection_block)
        pii_check       = ai_merge_pii(pii_check, ai_result)
        secret_check    = ai_merge_secret(secret_check, ai_result, secret_action)
      end

      checks = [pii_check, injection_check, secret_check, length_check]

      regex_risk = compute_risk_score(
        pii:       pii_check[:detected],
        injection: injection_check[:injection_attempt],
        secret:    secret_check[:leaked],
        checks:    checks
      )

      ai_risk_score = ai_result && coerce_risk_score(ai_result[:risk_score])
      risk_score    = ai_risk_score ? [regex_risk, ai_risk_score].max.round(4) : regex_risk

      result = {
        allowed:           checks.all? { |c| c[:allowed] },
        pii_detected:      pii_check[:detected],
        injection_attempt: injection_check[:injection_attempt],
        secret_leaked:     secret_check[:leaked],
        risk_score:        risk_score,
        checks:            checks
      }

      result[:ai_analysis] = ai_result if ai_result
      result
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

    private_class_method def self.skipped_check(type, **fields)
      { type: type, allowed: true, skipped: true, **fields }
    end

    private_class_method def self.run_ai_analysis(analyzer, text, context)
      result = analyzer.call(text, context)
      return { error: "ai_analyzer must return a Hash" } unless result.is_a?(Hash)
      result.slice(:injection_attempt, :pii_detected, :secret_leaked, :risk_score, :reason)
    rescue => e
      { error: e.message.to_s[0..200] }
    end

    private_class_method def self.ai_merge_injection(check, ai_result, injection_block)
      return check unless ai_result[:injection_attempt]
      check.merge(injection_attempt: true, allowed: !injection_block, ai_flagged: true)
    end

    private_class_method def self.ai_merge_pii(check, ai_result)
      return check unless ai_result[:pii_detected]
      check.merge(detected: true, ai_flagged: true)
    end

    private_class_method def self.ai_merge_secret(check, ai_result, secret_action)
      return check unless ai_result[:secret_leaked]
      count = check[:count].to_i
      check.merge(leaked: true, allowed: secret_action != "block", count: [count, 1].max, ai_flagged: true)
    end

    # A hook is untrusted input: coerce risk_score defensively so a NaN,
    # Infinity, wrong type, or garbage string from a flaky LLM response can
    # never propagate into a Float#clamp comparison and raise. Returns nil
    # (treated as "no usable score") rather than a fallback number, so a
    # broken hook never silently produces a specific-looking wrong score.
    private_class_method def self.coerce_risk_score(value)
      float = Float(value, exception: false)
      return nil if float.nil? || !float.finite?
      float.clamp(0.0, 1.0)
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
