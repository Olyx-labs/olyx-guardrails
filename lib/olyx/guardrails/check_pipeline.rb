# frozen_string_literal: true

module Olyx
  module Guardrails
    # Applies optional analysis and builds the public decision contract.
    module CheckPipeline
      module_function

      def call(source, checks, policy:, llm_provider:)
        merged, analysis = CheckAnalyzer.call(
          checks, provider: llm_provider, source: source, policy: policy
        )
        CheckResultBuilder.call(merged, analysis, policy)
      end
    end
  end
end
