# frozen_string_literal: true

require_relative 'risk/ai_score'
require_relative 'risk/deterministic_score'

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
        deterministic = Risk::DeterministicScore.call(@checks, @ordered_checks)
        ai_risk = Risk::AiScore.call(@ai_result)
        ai_risk ? [deterministic, ai_risk].max.round(4) : deterministic
      end
    end
  end
end
