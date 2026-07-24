# frozen_string_literal: true

require_relative 'risk_scorer'

module Olyx
  module Guardrails
    # Presents merged checks as the stable public decision contract.
    module CheckResultBuilder
      CHECK_ORDER = %i[pii injection secret policy length llm].freeze

      module_function

      def call(checks, analysis, policy)
        ordered = CHECK_ORDER.filter_map { |type| checks[type] }
        base_result(checks, ordered, policy)
          .merge(risk(checks, ordered, analysis))
          .merge(analysis_result(analysis))
      end

      def base_result(checks, ordered, policy)
        detection(checks, ordered).merge(policy(checks[:policy], policy))
      end

      def detection(checks, ordered)
        {
          allowed: ordered.all? { |check| check[:allowed] },
          pii_detected: checks[:pii][:detected],
          injection_attempt: checks[:injection][:injection_attempt],
          secret_leaked: checks[:secret][:leaked]
        }
      end

      def policy(check, configuration)
        {
          policy_name: configuration.name,
          policy_violated: check[:violated],
          policy_findings: check[:findings]
        }
      end

      def risk(checks, ordered, analysis)
        { risk_score: RiskScorer.call(checks, ordered, analysis), checks: ordered }
      end

      def analysis_result(analysis)
        analysis ? { llm_analysis: analysis } : {}
      end
      private_class_method :base_result, :detection, :policy, :risk, :analysis_result
    end
  end
end
