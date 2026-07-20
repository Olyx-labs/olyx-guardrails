# frozen_string_literal: true

require_relative "ai_analysis"
require_relative "injection_detector"
require_relative "pii_scrubber"
require_relative "secret_scanner"
require_relative "validation"

module Olyx
  module Guardrails
    # Executes and combines deterministic and optional semantic checks for one
    # input. The public facade remains {Guardrails.check}.
    class CheckRunner
      CHECK_ORDER = %i[pii injection secret length].freeze

      def self.call(input, **options)
        new(input, **options).call
      end

      def initialize(
        input,
        max_input_length:,
        block_injections:,
        block_secrets:,
        custom_patterns:,
        ai_analyzer:
      )
        @source = input.to_s
        @max_input_length = max_input_length
        @block_injections = block_injections
        @block_secrets = block_secrets
        @custom_patterns = custom_patterns
        @ai_analyzer = ai_analyzer
        validate_options!
      end

      def call
        checks = initial_checks
        checks, ai_result = apply_ai_analysis(checks)
        build_result(checks, ai_result)
      end

      private

      def validate_options!
        Validation.non_negative_integer!(@max_input_length, name: "max_input_length")
        Validation.boolean!(@block_injections, name: "block_injections")
        Validation.boolean!(@block_secrets, name: "block_secrets")
        Validation.array_of!(@custom_patterns, String, name: "custom_patterns")
        Validation.callable_or_nil!(@ai_analyzer, name: "ai_analyzer")

        # Compile configuration even when an oversized input skips scanning.
        SecretScanner.scan("", custom_patterns: @custom_patterns)
      end

      def initial_checks
        length_check = check_length
        content_checks = length_check[:allowed] ? scanned_content_checks : skipped_content_checks
        content_checks.merge(length: length_check)
      end

      def scanned_content_checks
        {
          pii: check_pii,
          injection: check_injection,
          secret: check_secret
        }
      end

      def skipped_content_checks
        {
          pii: skipped_check("pii", detected: false),
          injection: skipped_check("injection", injection_attempt: false, patterns: []),
          secret: skipped_check("secret", leaked: false, count: 0)
        }
      end

      def check_pii
        detected = PiiScrubber.scrub(@source) != @source
        { type: "pii", allowed: true, detected: detected }
      end

      def check_injection
        scan = InjectionDetector.scan([ { "role" => "user", "content" => @source } ])
        attempt = scan[:injection_attempt]
        {
          type: "injection",
          allowed: !attempt || !@block_injections,
          injection_attempt: attempt,
          patterns: scan[:patterns]
        }
      end

      def check_secret
        scan = SecretScanner.scan(@source, custom_patterns: @custom_patterns)
        leaked = scan[:leaked]
        {
          type: "secret",
          allowed: !leaked || !@block_secrets,
          leaked: leaked,
          count: scan[:findings].size
        }
      end

      def check_length
        length = @source.length
        {
          type: "length",
          allowed: length <= @max_input_length,
          length: length,
          max_length: @max_input_length
        }
      end

      def skipped_check(type, **fields)
        { type: type, allowed: true, skipped: true, **fields }
      end

      def apply_ai_analysis(checks)
        return [checks, nil] unless @ai_analyzer && checks[:length][:allowed]

        ai_result = AiAnalysis.call(@ai_analyzer, @source, ai_context(checks))
        return [checks, ai_result] if ai_result[:error]

        [merge_ai_findings(checks, ai_result), ai_result]
      end

      def ai_context(checks)
        injection_check = checks[:injection]
        {
          pii_detected: checks[:pii][:detected],
          injection_attempt: injection_check[:injection_attempt],
          injection_patterns: injection_check[:patterns],
          secret_leaked: checks[:secret][:leaked]
        }
      end

      def merge_ai_findings(checks, ai_result)
        checks.merge(
          pii: merge_ai_pii(checks[:pii], ai_result),
          injection: merge_ai_injection(checks[:injection], ai_result),
          secret: merge_ai_secret(checks[:secret], ai_result)
        )
      end

      def merge_ai_injection(check, ai_result)
        return check unless ai_result[:injection_attempt]

        check.merge(injection_attempt: true, allowed: !@block_injections, ai_flagged: true)
      end

      def merge_ai_pii(check, ai_result)
        return check unless ai_result[:pii_detected]

        check.merge(detected: true, ai_flagged: true)
      end

      def merge_ai_secret(check, ai_result)
        return check unless ai_result[:secret_leaked]

        count = [check[:count].to_i, 1].max
        check.merge(leaked: true, allowed: !@block_secrets, count: count, ai_flagged: true)
      end

      def build_result(checks, ai_result)
        ordered_checks = CHECK_ORDER.map { |type| checks.fetch(type) }
        result = {
          allowed: ordered_checks.all? { |check| check[:allowed] },
          pii_detected: checks[:pii][:detected],
          injection_attempt: checks[:injection][:injection_attempt],
          secret_leaked: checks[:secret][:leaked],
          risk_score: combined_risk_score(checks, ordered_checks, ai_result),
          checks: ordered_checks
        }
        result[:ai_analysis] = ai_result if ai_result
        result
      end

      def combined_risk_score(checks, ordered_checks, ai_result)
        checks_risk = deterministic_risk_score(checks, ordered_checks)
        ai_risk = ai_result && coerce_risk_score(ai_result[:risk_score])
        ai_risk ? [checks_risk, ai_risk].max.round(4) : checks_risk
      end

      def deterministic_risk_score(checks, ordered_checks)
        score = 0.0
        score += INJECTION_RISK_WEIGHT if checks[:injection][:injection_attempt]
        score += SECRET_RISK_WEIGHT if checks[:secret][:leaked]
        score += PII_RISK_WEIGHT if checks[:pii][:detected]
        score += BLOCKED_RISK_WEIGHT if ordered_checks.any? { |check| !check[:allowed] }
        score.clamp(0.0, 1.0).round(4)
      end

      def coerce_risk_score(value)
        float = Float(value, exception: false)
        return nil if float.nil? || !float.finite?

        float.clamp(0.0, 1.0)
      end
    end
  end
end
