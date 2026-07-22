# frozen_string_literal: true

require_relative 'risk_scorer'
require_relative 'check_base_result'

module Olyx
  module Guardrails
    # Presents merged checks as the stable public decision contract.
    module CheckResultBuilder
      CHECK_ORDER = %i[pii injection secret policy length ai].freeze

      module_function

      def call(checks, analysis, policy)
        ordered = CHECK_ORDER.filter_map { |type| checks[type] }
        result = CheckBaseResult.call(checks, ordered, policy)
        result[:risk_score] = RiskScorer.call(checks, ordered, analysis)
        result[:checks] = ordered
        result[:ai_analysis] = analysis if analysis
        result
      end
    end
  end
end
