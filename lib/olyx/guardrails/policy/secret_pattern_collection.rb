# frozen_string_literal: true

require_relative '../secret_scanner'
require_relative '../validation'

module Olyx
  module Guardrails
    module PolicyComponents
      # Validates custom secret patterns once during policy construction.
      module SecretPatternCollection
        module_function

        def call(values)
          Validation.array_of!(values, String, name: 'policy secret_patterns')
          patterns = values.map { |pattern| pattern.dup.freeze }.freeze
          SecretScanner.scan('', custom_patterns: patterns)
          patterns
        end
      end
    end
  end
end
