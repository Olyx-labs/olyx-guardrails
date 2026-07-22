# frozen_string_literal: true

module Olyx
  module Guardrails
    module Ai
      # Finds the first analyzer flag whose value is not Boolean.
      module BooleanValidator
        KEYS = %i[injection_attempt pii_detected secret_leaked].freeze

        module_function

        def invalid_key(analysis)
          KEYS.find { |key| analysis.key?(key) && ![true, false].include?(analysis[key]) }
        end
      end
    end
  end
end
