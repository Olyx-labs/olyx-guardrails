# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyRuleComponents
      # Validates an optional human-readable rule description.
      module DescriptionValue
        module_function

        def call(value)
          return nil if value.nil?
          return value.dup.freeze if valid?(value)

          raise ArgumentError, 'policy rule description must be a String of 1..500 characters or nil'
        end

        def valid?(value)
          value.is_a?(String) && !value.strip.empty? && value.length <= 500
        end
        private_class_method :valid?
      end
    end
  end
end
