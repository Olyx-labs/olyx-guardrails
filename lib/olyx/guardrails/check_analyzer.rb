# frozen_string_literal: true

require_relative 'llm_analysis'
require_relative 'llm_context_builder'
require_relative 'llm_failure_handler'
require_relative 'llm_finding_merger'

module Olyx
  module Guardrails
    # Runs optional semantic analysis and merges valid findings.
    module CheckAnalyzer
      module_function

      def call(checks, provider:, source:, policy:)
        return [checks, nil] unless provider && checks[:length][:allowed]

        analysis = LlmAnalysis.call(provider, source, LlmContextBuilder.call(checks))
        [merge(checks, analysis, policy), analysis]
      end

      def merge(checks, analysis, policy)
        return LlmFailureHandler.call(checks, analysis, policy.llm_failure_mode) if analysis[:error]

        LlmFindingMerger.call(checks, analysis, policy)
      end
      private_class_method :merge
    end
  end
end
