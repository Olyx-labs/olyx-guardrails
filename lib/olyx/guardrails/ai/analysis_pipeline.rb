# frozen_string_literal: true

module Olyx
  module Guardrails
    module Ai
      # Applies normalization, selection, Boolean validation, and reason bounds.
      module AnalysisPipeline
        INVALID_SHAPE_ERROR = 'ai_analyzer must return a Hash or a schema model with deep_to_h/to_h'

        module_function

        def call(value)
          result = AnalysisNormalizer.call(value)
          return { error: INVALID_SHAPE_ERROR } unless result

          sanitized = ResultSanitizer.call(result)
          invalid_key = BooleanValidator.invalid_key(sanitized)
          return { error: "ai_analyzer #{invalid_key} must be true or false" } if invalid_key

          sanitized[:reason] = sanitized[:reason].to_s[0...500] if sanitized.key?(:reason)
          sanitized
        end
      end
    end
  end
end
