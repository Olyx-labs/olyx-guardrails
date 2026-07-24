# frozen_string_literal: true

require_relative 'risk/llm_score'
require_relative 'risk/deterministic_score'

module Olyx
  module Guardrails
    # Computes the bounded heuristic risk score from merged check results and
    # an optional LLM provider score.
    class RiskScorer
      def self.call(checks, ordered_checks, llm_result)
        new(checks, ordered_checks, llm_result).call
      end

      def initialize(checks, ordered_checks, llm_result)
        @checks = checks
        @ordered_checks = ordered_checks
        @llm_result = llm_result
      end

      def call
        deterministic = Risk::DeterministicScore.call(@checks, @ordered_checks)
        llm_risk = Risk::LlmScore.call(@llm_result)
        llm_risk ? [deterministic, llm_risk].max.round(4) : deterministic
      end
    end
  end
end
