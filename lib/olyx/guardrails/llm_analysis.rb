# frozen_string_literal: true

module Olyx
  module Guardrails
    # Validates the bounded provider contract; raw provider exceptions never escape.
    module LlmAnalysis
      PROVIDER_ERROR = 'llm_provider failed'
      INVALID_SHAPE_ERROR = 'llm_provider must return a Hash or a schema model with deep_to_h/to_h'
      BOOLEAN_KEYS = %i[injection_attempt pii_detected secret_leaked].freeze
      KEYS = [*BOOLEAN_KEYS, :risk_score, :reason].freeze

      module_function

      def call(provider, text, context)
        result = normalize(provider.call(text, context))
        return { error: INVALID_SHAPE_ERROR } unless result

        selected = select_fields(result)
        validation_error(selected) || bound_reason(selected)
      rescue StandardError
        { error: PROVIDER_ERROR }
      end

      def normalize(value)
        return value if value.is_a?(Hash)

        converted = convert(value)
        converted if converted.is_a?(Hash)
      end

      def convert(value)
        return value.deep_to_h if value.respond_to?(:deep_to_h)

        value.to_h if value.respond_to?(:to_h)
      end

      def select_fields(result)
        KEYS.each_with_object({}) do |key, output|
          source_key = result.key?(key) ? key : key.to_s
          output[key] = result[source_key] if result.key?(source_key)
        end
      end

      def validation_error(result)
        key = BOOLEAN_KEYS.find { |field| result.key?(field) && ![true, false].include?(result[field]) }
        { error: "llm_provider #{key} must be true or false" } if key
      end

      def bound_reason(result)
        result[:reason] = result[:reason].to_s[0...500] if result.key?(:reason)
        result
      end
      private_class_method :normalize, :convert, :select_fields, :validation_error, :bound_reason
    end
  end
end
