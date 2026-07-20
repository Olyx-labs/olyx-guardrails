# frozen_string_literal: true

require_relative "guardrails/version"
require_relative "guardrails/pii_scrubber"
require_relative "guardrails/injection_detector"
require_relative "guardrails/secret_scanner"

module Olyx
  # Guardrails is a standalone, in-process AI safety toolkit: PII redaction,
  # prompt-injection detection, and secret scanning, unified behind a single
  # `.check` entry point.
  module Guardrails
    INJECTION_RISK_WEIGHT = 0.50
    SECRET_RISK_WEIGHT    = 0.25
    PII_RISK_WEIGHT       = 0.10
    BLOCKED_RISK_WEIGHT   = 0.15

    # Runs the full guardrail suite (PII, injection, secret, and length
    # checks) on a single input in one call, optionally enriched by a
    # caller-supplied AI analyzer hook. Returns the same shape as
    # `GuardrailService#ruby_check` so olyx-api can delegate directly.
    #
    # The hook follows defense-in-depth: AI findings union with regex
    # findings — the hook can flag additional violations but cannot clear
    # existing ones. Exceptions raised by the hook are rescued; the error is
    # recorded in `ai_analysis[:error]` and the regex result stands.
    #
    # @param input [#to_s] the content to check; converted via `to_s`.
    # @param max_input_length [Integer] maximum allowed length. The `pii`,
    #   `injection`, and `secret` checks are skipped entirely (not just
    #   failed) when this is exceeded, so an oversized payload never pays
    #   their scanning cost.
    # @param block_injections [Boolean] whether a detected injection attempt
    #   makes the result `allowed: false`.
    # @param block_secrets [Boolean] whether a detected secret makes the
    #   result `allowed: false`.
    # @param custom_patterns [Array<String>] extra regex strings for secret
    #   scanning, in addition to the built-in patterns.
    # @param ai_analyzer [#call, nil] optional callable receiving
    #   `(text, context)` and returning a Hash. `context` carries
    #   `:pii_detected`, `:injection_attempt`, `:injection_patterns`, and
    #   `:secret_leaked` from the regex pass. The hook's return Hash may
    #   include any of `:injection_attempt`, `:pii_detected`,
    #   `:secret_leaked` (Boolean), `:risk_score` (Float in `0.0..1.0`, used
    #   when higher than the regex-derived score), and `:reason` (String,
    #   surfaced in `ai_analysis`). Not called when `max_input_length` is
    #   exceeded.
    # @return [Hash] `:allowed`, `:pii_detected`, `:injection_attempt`,
    #   `:secret_leaked` (all Boolean), `:risk_score` (Float in `0.0..1.0`),
    #   `:checks` (Array of per-check Hashes, one each for `pii`,
    #   `injection`, `secret`, `length`), and `:ai_analysis` (present only
    #   when `ai_analyzer` is supplied).
    def self.check(
      input,
      max_input_length: 10_000,
      block_injections: true,
      block_secrets: false,
      custom_patterns: [],
      ai_analyzer: nil
    )
      validate_check_options!(
        max_input_length: max_input_length,
        block_injections: block_injections,
        block_secrets: block_secrets,
        custom_patterns: custom_patterns,
        ai_analyzer: ai_analyzer
      )

      input_str    = input.to_s
      length_check = check_length(input_str, max_input_length)

      if length_check[:allowed]
        pii_check       = check_pii(input_str)
        injection_check = check_injection(input_str, block_injections)
        secret_check    = check_secret(input_str, block_secrets, custom_patterns)
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

      pii_check, injection_check, secret_check, ai_result = apply_ai_analysis(
        ai_analyzer, input_str, length_check, pii_check, injection_check, secret_check,
        block_injections: block_injections, block_secrets: block_secrets
      )

      checks = [pii_check, injection_check, secret_check, length_check]

      # Named checks_risk (not regex_risk) because by this point checks may
      # already include AI-merged findings, not just the regex scan.
      checks_risk = compute_risk_score(
        pii:       pii_check[:detected],
        injection: injection_check[:injection_attempt],
        secret:    secret_check[:leaked],
        checks:    checks
      )

      ai_risk_score = ai_result && coerce_risk_score(ai_result[:risk_score])
      risk_score    = ai_risk_score ? [checks_risk, ai_risk_score].max.round(4) : checks_risk

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

    # Redacts regex-detected PII and secrets as a transformation distinct from
    # {.check}. This method never makes an allow/block decision.
    #
    # @param input [#to_s] the content to redact.
    # @param max_input_length [Integer] maximum accepted input length.
    # @param custom_patterns [Array<String>] extra secret regex strings.
    # @return [Hash] `:text` (redacted), `:redacted`, `:pii_detected`,
    #   `:secret_leaked`, and safe, masked secret `:findings`.
    # @raise [ArgumentError] when an option is invalid or input is oversized.
    def self.redact(input, max_input_length: 10_000, custom_patterns: [])
      validate_max_input_length!(max_input_length)
      source = input.to_s
      raise ArgumentError, "input exceeds max_input_length" if source.length > max_input_length

      secret_result = SecretScanner.redact(source, custom_patterns: custom_patterns)
      redacted_text = PiiScrubber.scrub(secret_result[:text])

      {
        text:           redacted_text,
        redacted:       redacted_text != source,
        pii_detected:   PiiScrubber.scrub(source) != source,
        secret_leaked:  secret_result[:leaked],
        findings:       secret_result[:findings]
      }
    end

    # @param input_str [String]
    # @return [Hash] the `pii` check: `:type`, `:allowed` (always `true` —
    #   PII alone never blocks a request, it only feeds `risk_score`), and
    #   `:detected` (Boolean).
    private_class_method def self.check_pii(input_str)
      detected = PiiScrubber.scrub(input_str) != input_str
      { type: "pii", allowed: true, detected: detected }
    end

    # @param input_str [String]
    # @param block_injections [Boolean]
    # @return [Hash] the `injection` check: `:type`, `:allowed`,
    #   `:injection_attempt` (Boolean), and `:patterns` (Array of matched
    #   pattern details from InjectionDetector).
    private_class_method def self.check_injection(input_str, block_injections)
      result  = InjectionDetector.scan([ { "role" => "user", "content" => input_str } ])
      attempt = result[:injection_attempt]
      {
        type:              "injection",
        allowed:           !attempt || !block_injections,
        injection_attempt: attempt,
        patterns:          result[:patterns]
      }
    end

    # @param input_str [String]
    # @param block_secrets [Boolean]
    # @param custom_patterns [Array<String>]
    # @return [Hash] the `secret` check: `:type`, `:allowed`, `:leaked`
    #   (Boolean), and `:count` (Integer number of findings).
    private_class_method def self.check_secret(input_str, block_secrets, custom_patterns)
      result = SecretScanner.scan(input_str, custom_patterns: custom_patterns)
      leaked = result[:leaked]
      { type: "secret", allowed: !leaked || !block_secrets, leaked: leaked, count: result[:findings].size }
    end

    # @param input_str [String]
    # @param max_input_length [Integer]
    # @return [Hash] the `length` check: `:type`, `:allowed`, `:length`
    #   (Integer), and `:max_length` (Integer).
    private_class_method def self.check_length(input_str, max_input_length)
      exceeded = input_str.length > max_input_length
      { type: "length", allowed: !exceeded, length: input_str.length, max_length: max_input_length }
    end

    # Builds a placeholder check hash for a scan that was skipped because
    # `max_input_length` was already exceeded.
    #
    # @param type [String] the check's `:type` value.
    # @param fields [Hash] extra fields merged into the result.
    # @return [Hash] `:type`, `:allowed` (always `true`), `:skipped` (always
    #   `true`), plus `fields`.
    private_class_method def self.skipped_check(type, **fields)
      { type: type, allowed: true, skipped: true, **fields }
    end

    # Runs the hook (when applicable) and merges its findings into the three
    # content checks.
    #
    # @param analyzer [#call, nil]
    # @param input_str [String]
    # @param length_check [Hash]
    # @param pii_check [Hash]
    # @param injection_check [Hash]
    # @param secret_check [Hash]
    # @param block_injections [Boolean]
    # @param block_secrets [Boolean]
    # @return [Array(Hash, Hash, Hash, Hash)] `[pii_check, injection_check,
    #   secret_check, ai_result]` — `ai_result` is `nil` when there's no hook
    #   or length already failed, so callers can tell "didn't run" apart
    #   from "ran, found nothing".
    private_class_method def self.apply_ai_analysis(
      analyzer, input_str, length_check, pii_check, injection_check, secret_check,
      block_injections:, block_secrets:
    )
      return [pii_check, injection_check, secret_check, nil] unless analyzer && length_check[:allowed]

      ai_result = run_ai_analysis(analyzer, input_str, {
        pii_detected:       pii_check[:detected],
        injection_attempt:  injection_check[:injection_attempt],
        injection_patterns: injection_check[:patterns],
        secret_leaked:      secret_check[:leaked]
      })

      return [pii_check, injection_check, secret_check, ai_result] if ai_result[:error]

      [
        ai_merge_pii(pii_check, ai_result),
        ai_merge_injection(injection_check, ai_result, block_injections),
        ai_merge_secret(secret_check, ai_result, block_secrets),
        ai_result
      ]
    end

    # Calls the hook and sanitizes its return value down to the keys
    # `Olyx::Guardrails.check` understands, so an untrusted hook can't
    # inject arbitrary keys into the result.
    #
    # @param analyzer [#call]
    # @param text [String]
    # @param context [Hash]
    # @return [Hash] a subset of `:injection_attempt`, `:pii_detected`,
    #   `:secret_leaked`, `:risk_score`, `:reason`, or `{ error: String }` if
    #   the hook raised or returned something other than a Hash.
    private_class_method def self.run_ai_analysis(analyzer, text, context)
      result = analyzer.call(text, context)
      return { error: "ai_analyzer must return a Hash" } unless result.is_a?(Hash)

      sanitized = result.slice(:injection_attempt, :pii_detected, :secret_leaked, :risk_score, :reason)
      %i[injection_attempt pii_detected secret_leaked].each do |key|
        next unless sanitized.key?(key)
        return { error: "ai_analyzer #{key} must be true or false" } unless [true, false].include?(sanitized[key])
      end
      sanitized[:reason] = sanitized[:reason].to_s[0...500] if sanitized.key?(:reason)
      sanitized
    rescue => e
      { error: e.message.to_s[0..200] }
    end

    # @param check [Hash] the current `injection` check.
    # @param ai_result [Hash]
    # @param block_injections [Boolean]
    # @return [Hash] `check`, or `check` merged with the AI's finding when
    #   `ai_result[:injection_attempt]` is truthy.
    private_class_method def self.ai_merge_injection(check, ai_result, block_injections)
      return check unless ai_result[:injection_attempt]
      check.merge(injection_attempt: true, allowed: !block_injections, ai_flagged: true)
    end

    # @param check [Hash] the current `pii` check.
    # @param ai_result [Hash]
    # @return [Hash] `check`, or `check` merged with the AI's finding when
    #   `ai_result[:pii_detected]` is truthy.
    private_class_method def self.ai_merge_pii(check, ai_result)
      return check unless ai_result[:pii_detected]
      check.merge(detected: true, ai_flagged: true)
    end

    # @param check [Hash] the current `secret` check.
    # @param ai_result [Hash]
    # @param block_secrets [Boolean]
    # @return [Hash] `check`, or `check` merged with the AI's finding when
    #   `ai_result[:secret_leaked]` is truthy. `:count` is bumped to at
    #   least 1 so `leaked: true` never sits alongside a stale `count: 0`.
    private_class_method def self.ai_merge_secret(check, ai_result, block_secrets)
      return check unless ai_result[:secret_leaked]
      count = check[:count].to_i
      check.merge(leaked: true, allowed: !block_secrets, count: [count, 1].max, ai_flagged: true)
    end

    private_class_method def self.validate_check_options!(
      max_input_length:, block_injections:, block_secrets:, custom_patterns:, ai_analyzer:
    )
      validate_max_input_length!(max_input_length)
      unless [true, false].include?(block_injections)
        raise ArgumentError, "block_injections must be true or false"
      end
      unless [true, false].include?(block_secrets)
        raise ArgumentError, "block_secrets must be true or false"
      end
      unless custom_patterns.is_a?(Array) && custom_patterns.all? { |pattern| pattern.is_a?(String) }
        raise ArgumentError, "custom_patterns must be an Array of String values"
      end
      unless ai_analyzer.nil? || ai_analyzer.respond_to?(:call)
        raise ArgumentError, "ai_analyzer must respond to call"
      end
    end

    private_class_method def self.validate_max_input_length!(max_input_length)
      unless max_input_length.is_a?(Integer) && max_input_length >= 0
        raise ArgumentError, "max_input_length must be a non-negative Integer"
      end
    end

    # A hook is untrusted input: coerce risk_score defensively so a NaN,
    # Infinity, wrong type, or garbage string from a flaky LLM response can
    # never propagate into a `Float#clamp` comparison and raise. Returns
    # `nil` (treated as "no usable score") rather than a fallback number, so
    # a broken hook never silently produces a specific-looking wrong score.
    #
    # @param value [Object] the hook's raw `:risk_score` value.
    # @return [Float, nil] a value clamped to `0.0..1.0`, or `nil` if `value`
    #   isn't a finite number.
    private_class_method def self.coerce_risk_score(value)
      float = Float(value, exception: false)
      return nil if float.nil? || !float.finite?
      float.clamp(0.0, 1.0)
    end

    # @param pii [Boolean]
    # @param injection [Boolean]
    # @param secret [Boolean]
    # @param checks [Array<Hash>]
    # @return [Float] a weighted heuristic score in `0.0..1.0`.
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
