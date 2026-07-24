# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyComponents
      # Converts policy rule Hashes into immutable PolicyRule values.
      module RuleNormalizer
        ERROR = 'policy rules must be an Array of PolicyRule or Hash values'

        module_function

        def call(value)
          return value if value.is_a?(PolicyRule)
          return PolicyRule.new(**ConfigurationHash.call(value)) if value.is_a?(Hash)

          raise ArgumentError, ERROR
        end
      end
    end
  end
end
