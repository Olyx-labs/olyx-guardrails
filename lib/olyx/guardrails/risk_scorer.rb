# frozen_string_literal: true

module Olyx
  module Guardrails
    # Computes the bounded heuristic risk score from merged check results and
    # an optional analyzer score.
    class RiskScorer
      def self.call(checks, ordered_checks, ai_result)
        new(checks, ordered_checks, ai_result).call
      end

      def initialize(checks, ordered_checks, ai_result)
        @checks = checks
        @ordered_checks = ordered_checks
        @ai_result = ai_result
      end

      def call
        deterministic = deterministic_score
        ai_risk = @ai_result && coerce(@ai_result[:risk_score])
        ai_risk ? [deterministic, ai_risk].max.round(4) : deterministic
      end

      private

      def deterministic_score
        score = 0.0
        score += INJECTION_RISK_WEIGHT if @checks[:injection][:injection_attempt]
        score += SECRET_RISK_WEIGHT if @checks[:secret][:leaked]
        score += PII_RISK_WEIGHT if @checks[:pii][:detected]
        score += BLOCKED_RISK_WEIGHT if @ordered_checks.any? { |check| !check[:allowed] }
        score.clamp(0.0, 1.0).round(4)
      end

      def coerce(value)
        float = Float(value, exception: false)
        return nil if float.nil? || !float.finite?

        float.clamp(0.0, 1.0)
      end
    end
  end
end
