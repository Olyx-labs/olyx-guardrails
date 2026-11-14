# frozen_string_literal: true

require_relative 'risk_scorer'

module Olyx
  module Guardrails
    # Presents merged checks as the stable public decision contract.
    module CheckResultBuilder
      CHECK_ORDER = %i[pii injection secret policy length llm].freeze

      module_function

      # Keep the fixed public contract together rather than splitting its fields across helpers.
      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
      def call(checks, analysis, policy)
        ordered = CHECK_ORDER.filter_map { |type| checks[type] }
        result = {
          allowed: ordered.all? { |check| check[:allowed] },
          pii_detected: checks[:pii][:detected],
          injection_attempt: checks[:injection][:injection_attempt],
          secret_leaked: checks[:secret][:leaked],
          policy_name: policy.name,
          policy_violated: checks[:policy][:violated],
          policy_findings: checks[:policy][:findings],
          risk_score: RiskScorer.call(checks, analysis),
          checks: ordered
        }
        result[:llm_analysis] = analysis if analysis
        result
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength
    end
  end
end
