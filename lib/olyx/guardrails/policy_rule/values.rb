# frozen_string_literal: true

require_relative 'name_value'
require_relative 'text_values'

module Olyx
  module Guardrails
    module PolicyRuleComponents
      # Validates non-pattern policy-rule values.
      module Values
        module_function

        def name(value)
          NameValue.call(value)
        end

        def boolean(value)
          return value if [true, false].include?(value)

          raise ArgumentError, 'policy rule block must be true or false'
        end

        def description(value)
          TextValues.description(value)
        end

        def replacement(value)
          TextValues.replacement(value)
        end
      end
    end
  end
end
