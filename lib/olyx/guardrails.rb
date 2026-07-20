# frozen_string_literal: true

require_relative "guardrails/version"
require_relative "guardrails/validation"
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
    CHECK_ORDER = %i[pii injection secret length].freeze
    AI_ANALYSIS_KEYS      = %i[
      injection_attempt
      pii_detected
      secret_leaked
      risk_score
      reason
    ].freeze

    # Runs the full guardrail suite (PII, injection, secret, and length
    # checks) on a single input in one call, optionally enriched by a
    # caller-supplied AI analyzer hook.
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
    #   `(text, context)` and returning a Hash or an OpenAI schema-model
    #   instance. `context` carries
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

      source = input.to_s
      checks = initial_checks(
        source,
        max_input_length: max_input_length,
        block_injections: block_injections,
        block_secrets: block_secrets,
        custom_patterns: custom_patterns
      )
      checks, ai_result = apply_ai_analysis(
        ai_analyzer, source, checks,
        block_injections: block_injections, block_secrets: block_secrets
      )
      build_check_result(checks, ai_result)
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
      length = input_str.length
      { type: "length", allowed: length <= max_input_length, length: length, max_length: max_input_length }
    end

    private_class_method def self.initial_checks(
      source, max_input_length:, block_injections:, block_secrets:, custom_patterns:
    )
      length_check = check_length(source, max_input_length)
      content_checks = if length_check[:allowed]
        scanned_content_checks(source, block_injections, block_secrets, custom_patterns)
      else
        skipped_content_checks
      end
      content_checks.merge(length: length_check)
    end

    private_class_method def self.scanned_content_checks(
      source, block_injections, block_secrets, custom_patterns
    )
      {
        pii:       check_pii(source),
        injection: check_injection(source, block_injections),
        secret:    check_secret(source, block_secrets, custom_patterns)
      }
    end

    # Input already exceeds max_input_length, so expensive content scans are
    # represented explicitly as skipped.
    private_class_method def self.skipped_content_checks
      {
        pii:       skipped_check("pii", detected: false),
        injection: skipped_check("injection", injection_attempt: false, patterns: []),
        secret:    skipped_check("secret", leaked: false, count: 0)
      }
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
    # @param checks [Hash]
    # @param block_injections [Boolean]
    # @param block_secrets [Boolean]
    # @return [Array(Hash, Hash)] `[checks, ai_result]` — `ai_result` is `nil` when there's no hook
    #   or length already failed, so callers can tell "didn't run" apart
    #   from "ran, found nothing".
    private_class_method def self.apply_ai_analysis(
      analyzer, input_str, checks, block_injections:, block_secrets:
    )
      return [checks, nil] unless analyzer && checks[:length][:allowed]

      ai_result = run_ai_analysis(analyzer, input_str, ai_context(checks))
      return [checks, ai_result] if ai_result[:error]

      merged = checks.merge(
        pii: ai_merge_pii(checks[:pii], ai_result),
        injection: ai_merge_injection(checks[:injection], ai_result, block_injections),
        secret: ai_merge_secret(checks[:secret], ai_result, block_secrets)
      )
      [merged, ai_result]
    end

    private_class_method def self.ai_context(checks)
      injection_check = checks[:injection]
      {
        pii_detected:       checks[:pii][:detected],
        injection_attempt:  injection_check[:injection_attempt],
        injection_patterns: injection_check[:patterns],
        secret_leaked:      checks[:secret][:leaked]
      }
    end

    # Calls the hook, converts Hash-like schema models, and sanitizes the
    # result down to the keys `Olyx::Guardrails.check` understands, so an
    # untrusted hook can't inject arbitrary keys into the result.
    #
    # @param analyzer [#call]
    # @param text [String]
    # @param context [Hash]
    # @return [Hash] a subset of `:injection_attempt`, `:pii_detected`,
    #   `:secret_leaked`, `:risk_score`, `:reason`, or `{ error: String }` if
    #   the hook raised or returned something other than a Hash or schema
    #   model.
    private_class_method def self.run_ai_analysis(analyzer, text, context)
      result = normalize_ai_analysis(analyzer.call(text, context))
      return invalid_ai_shape unless result

      sanitized = sanitize_ai_analysis(result)
      invalid_boolean = invalid_ai_boolean(sanitized)
      return { error: "ai_analyzer #{invalid_boolean} must be true or false" } if invalid_boolean

      sanitized[:reason] = sanitized[:reason].to_s[0...500] if sanitized.key?(:reason)
      sanitized
    rescue => error
      { error: error.message.to_s[0..200] }
    end

    private_class_method def self.invalid_ai_shape
      { error: "ai_analyzer must return a Hash or a schema model with deep_to_h/to_h" }
    end

    private_class_method def self.sanitize_ai_analysis(result)
      AI_ANALYSIS_KEYS.each_with_object({}) do |key, output|
        string_key = key.to_s
        symbol_value = result[key]
        has_symbol = result.key?(key)
        has_string = result.key?(string_key)
        output[key] = has_symbol ? symbol_value : result[string_key] if has_symbol || has_string
      end
    end

    private_class_method def self.invalid_ai_boolean(analysis)
      %i[injection_attempt pii_detected secret_leaked].find do |key|
        analysis.key?(key) && ![true, false].include?(analysis[key])
      end
    end

    # OpenAI structured-output objects implement `#deep_to_h`; accepting that
    # protocol keeps the core independent of the optional OpenAI SDK. A plain
    # `#to_h` fallback supports other schema libraries with the same shape.
    #
    # @param value [Object]
    # @return [Hash, nil]
    private_class_method def self.normalize_ai_analysis(value)
      return value if value.is_a?(Hash)

      converted =
        if value.respond_to?(:deep_to_h)
          value.deep_to_h
        elsif value.respond_to?(:to_h)
          value.to_h
        end

      converted if converted.is_a?(Hash)
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
      validate_boolean_option!(block_injections, "block_injections")
      validate_boolean_option!(block_secrets, "block_secrets")
      Validation.array_of!(custom_patterns, String, name: "custom_patterns")
      validate_ai_analyzer!(ai_analyzer)

      # Compile at the API boundary so invalid configuration fails at boot even
      # when this particular input is oversized and content scans are skipped.
      SecretScanner.scan("", custom_patterns: custom_patterns)
    end

    private_class_method def self.validate_boolean_option!(value, name)
      raise ArgumentError, "#{name} must be true or false" unless [true, false].include?(value)
    end

    private_class_method def self.validate_ai_analyzer!(ai_analyzer)
      return if ai_analyzer.nil? || ai_analyzer.respond_to?(:call)

      raise ArgumentError, "ai_analyzer must respond to call"
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
      weighted_signals = [
        [injection, INJECTION_RISK_WEIGHT],
        [secret, SECRET_RISK_WEIGHT],
        [pii, PII_RISK_WEIGHT]
      ]
      score = weighted_signals.sum { |detected, weight| detected ? weight : 0.0 }
      score += BLOCKED_RISK_WEIGHT if checks.any? { |check| !check[:allowed] }
      score.clamp(0.0, 1.0).round(4)
    end

    private_class_method def self.build_check_result(checks, ai_result)
      ordered_checks = CHECK_ORDER.map { |type| checks.fetch(type) }
      result = {
        allowed:           ordered_checks.all? { |check| check[:allowed] },
        pii_detected:      checks[:pii][:detected],
        injection_attempt: checks[:injection][:injection_attempt],
        secret_leaked:     checks[:secret][:leaked],
        risk_score:        combined_risk_score(checks, ordered_checks, ai_result),
        checks:            ordered_checks
      }
      result[:ai_analysis] = ai_result if ai_result
      result
    end

    private_class_method def self.combined_risk_score(checks, ordered_checks, ai_result)
      checks_risk = compute_risk_score(
        pii: checks[:pii][:detected],
        injection: checks[:injection][:injection_attempt],
        secret: checks[:secret][:leaked],
        checks: ordered_checks
      )
      ai_risk = ai_result && coerce_risk_score(ai_result[:risk_score])
      ai_risk ? [checks_risk, ai_risk].max.round(4) : checks_risk
    end
  end
end
