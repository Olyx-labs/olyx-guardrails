# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyRuleComponents
      # Validates and freezes a policy-rule identifier.
      module NameValue
        FORMAT = /\A[a-z][a-z0-9_.:-]*\z/i

        module_function

        def call(value)
          normalized = value.to_s
          valid = (value.is_a?(String) || value.is_a?(Symbol)) && normalized.match?(FORMAT)
          raise ArgumentError, 'policy rule name must be a String or Symbol identifier' unless valid

          normalized.dup.freeze
        end
      end
    end
  end
end
