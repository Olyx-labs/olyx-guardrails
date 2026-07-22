# frozen_string_literal: true

require_relative 'ai_failure_handler'

module Olyx
  module Guardrails
    # Runs optional semantic analysis and merges valid findings.
    module CheckAnalyzer
      module_function

      def call(checks, analyzer:, source:, policy:)
        return [checks, nil] unless analyzer && checks[:length][:allowed]

        analysis = AiAnalysis.call(analyzer, source, AiContextBuilder.call(checks))
        [merge(checks, analysis, policy), analysis]
      end

      def merge(checks, analysis, policy)
        return AiFailureHandler.call(checks, analysis, policy.ai_failure_mode) if analysis[:error]

        AiFindingMerger.call(checks, analysis, policy)
      end
      private_class_method :merge
    end
  end
end
