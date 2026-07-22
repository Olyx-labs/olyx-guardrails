# frozen_string_literal: true

require_relative 'ai/analysis_normalizer'
require_relative 'ai/analysis_pipeline'
require_relative 'ai/boolean_validator'
require_relative 'ai/result_sanitizer'

module Olyx
  module Guardrails
    # Normalizes and bounds responses from an untrusted optional AI analyzer.
    class AiAnalysis
      def self.call(analyzer, text, context)
        new(analyzer, text, context).call
      end

      def initialize(analyzer, text, context)
        @analyzer = analyzer
        @text = text
        @context = context
      end

      def call
        Ai::AnalysisPipeline.call(@analyzer.call(@text, @context))
      rescue StandardError => error
        { error: error.message.to_s[0..200] }
      end
    end
  end
end
