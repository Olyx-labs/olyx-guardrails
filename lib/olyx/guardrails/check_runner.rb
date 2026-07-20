# frozen_string_literal: true

require_relative "ai_analysis"
require_relative "check_set"
require_relative "risk_scorer"
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
        checks = CheckSet.call(
          @source,
          max_input_length: @max_input_length,
          block_injections: @block_injections,
          block_secrets: @block_secrets,
          custom_patterns: @custom_patterns
        )
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
          risk_score: RiskScorer.call(checks, ordered_checks, ai_result),
          checks: ordered_checks
        }
        result[:ai_analysis] = ai_result if ai_result
        result
      end

    end
  end
end
