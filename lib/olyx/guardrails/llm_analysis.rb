# frozen_string_literal: true

require_relative 'llm/analysis_pipeline'

module Olyx
  module Guardrails
    # Normalizes and bounds responses from an untrusted optional LLM provider.
    class LlmAnalysis
      PROVIDER_ERROR = 'llm_provider failed'

      def self.call(provider, text, context)
        new(provider, text, context).call
      end

      def initialize(provider, text, context)
        @provider = provider
        @text = text
        @context = context
      end

      def call
        Llm::AnalysisPipeline.call(@provider.call(@text, @context))
      rescue StandardError
        { error: PROVIDER_ERROR }
      end
    end
  end
end
