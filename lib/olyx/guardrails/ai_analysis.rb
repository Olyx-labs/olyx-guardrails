# frozen_string_literal: true

module Olyx
  module Guardrails
    # Normalizes and bounds responses from an untrusted optional AI analyzer.
    class AiAnalysis
      RESULT_KEYS = %i[
        injection_attempt
        pii_detected
        secret_leaked
        risk_score
        reason
      ].freeze
      BOOLEAN_KEYS = %i[injection_attempt pii_detected secret_leaked].freeze
      INVALID_SHAPE_ERROR =
        "ai_analyzer must return a Hash or a schema model with deep_to_h/to_h"

      def self.call(analyzer, text, context)
        new(analyzer, text, context).call
      end

      def initialize(analyzer, text, context)
        @analyzer = analyzer
        @text = text
        @context = context
      end

      def call
        result = normalize(@analyzer.call(@text, @context))
        return { error: INVALID_SHAPE_ERROR } unless result

        sanitized = sanitize(result)
        invalid_key = invalid_boolean_key(sanitized)
        return { error: "ai_analyzer #{invalid_key} must be true or false" } if invalid_key

        sanitized[:reason] = sanitized[:reason].to_s[0...500] if sanitized.key?(:reason)
        sanitized
      rescue => error
        { error: error.message.to_s[0..200] }
      end

      private

      def sanitize(result)
        RESULT_KEYS.each_with_object({}) do |key, output|
          value, present = result_value(result, key)
          output[key] = value if present
        end
      end

      def result_value(result, key)
        return [result[key], true] if result.key?(key)

        string_key = key.to_s
        [result[string_key], result.key?(string_key)]
      end

      def invalid_boolean_key(analysis)
        BOOLEAN_KEYS.find do |key|
          analysis.key?(key) && ![true, false].include?(analysis[key])
        end
      end

      def normalize(value)
        return value if value.is_a?(Hash)

        converted = convert_hash_like(value)
        converted if converted.is_a?(Hash)
      end

      def convert_hash_like(value)
        return value.deep_to_h if value.respond_to?(:deep_to_h)
        return value.to_h if value.respond_to?(:to_h)
      end
    end
  end
end
