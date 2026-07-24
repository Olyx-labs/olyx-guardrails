# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyComponents
      # Validates and freezes an operator-facing policy identifier.
      module Name
        module_function

        def call(value)
          return value.dup.freeze if valid?(value)

          raise ArgumentError, 'policy name must be a String of 1..100 characters'
        end

        def valid?(value)
          value.is_a?(String) && !value.strip.empty? && value.length <= 100
        end
        private_class_method :valid?
      end
    end
  end
end
