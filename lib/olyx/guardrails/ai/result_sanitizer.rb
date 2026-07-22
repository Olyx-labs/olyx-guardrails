# frozen_string_literal: true

module Olyx
  module Guardrails
    module Ai
      # Selects the bounded analyzer contract from an untrusted result Hash.
      module ResultSanitizer
        KEYS = %i[injection_attempt pii_detected secret_leaked risk_score reason].freeze

        module_function

        def call(result)
          KEYS.each_with_object({}) do |key, output|
            value, present = value_for(result, key)
            output[key] = value if present
          end
        end

        def value_for(result, key)
          return [result[key], true] if result.key?(key)

          string_key = key.to_s
          [result[string_key], result.key?(string_key)]
        end
        private_class_method :value_for
      end
    end
  end
end
