# frozen_string_literal: true

module Olyx
  module Guardrails
    module Llm
      # Converts supported schema-model results into Hash values.
      module AnalysisNormalizer
        module_function

        def call(value)
          return value if value.is_a?(Hash)

          converted = convert(value)
          converted if converted.is_a?(Hash)
        end

        def convert(value)
          return value.deep_to_h if value.respond_to?(:deep_to_h)

          value.to_h if value.respond_to?(:to_h)
        end
        private_class_method :convert
      end
    end
  end
end
