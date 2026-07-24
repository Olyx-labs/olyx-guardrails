# frozen_string_literal: true

require_relative 'description_value'
require_relative 'replacement_value'

module Olyx
  module Guardrails
    module PolicyRuleComponents
      # Validates human-readable rule description and replacement values.
      module TextValues
        module_function

        def description(value)
          DescriptionValue.call(value)
        end

        def replacement(value)
          ReplacementValue.call(value)
        end
      end
    end
  end
end
