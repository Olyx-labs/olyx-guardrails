# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyRuleComponents
      # Validates a bounded single-line rule replacement.
      module ReplacementValue
        module_function

        def call(value)
          return value.dup.freeze if valid?(value)

          raise ArgumentError, 'policy rule replacement must be a single-line String of 1..100 characters'
        end

        def valid?(value)
          value.is_a?(String) && bounded?(value) && single_line?(value)
        end

        def bounded?(value) = !value.empty? && value.length <= 100
        def single_line?(value) = !value.match?(/[\r\n\t]/)
        private_class_method :bounded?, :single_line?, :valid?
      end
    end
  end
end
