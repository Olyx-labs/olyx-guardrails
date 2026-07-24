# frozen_string_literal: true

require_relative 'analysis_normalizer'
require_relative 'boolean_validator'
require_relative 'result_sanitizer'

module Olyx
  module Guardrails
    module Llm
      # Applies normalization, selection, Boolean validation, and reason bounds.
      module AnalysisPipeline
        INVALID_SHAPE_ERROR = 'llm_provider must return a Hash or a schema model with deep_to_h/to_h'

        module_function

        def call(value)
          result = AnalysisNormalizer.call(value)
          return { error: INVALID_SHAPE_ERROR } unless result

          sanitized = ResultSanitizer.call(result)
          validation_error(sanitized) || bound_reason(sanitized)
        end

        def validation_error(result)
          invalid_key = BooleanValidator.invalid_key(result)
          { error: "llm_provider #{invalid_key} must be true or false" } if invalid_key
        end

        def bound_reason(result)
          result[:reason] = result[:reason].to_s[0...500] if result.key?(:reason)
          result
        end
        private_class_method :validation_error, :bound_reason
      end
    end
  end
end
