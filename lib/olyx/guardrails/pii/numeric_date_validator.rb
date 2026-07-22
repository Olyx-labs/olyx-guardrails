# frozen_string_literal: true

require_relative 'ambiguous_numeric_date'
require_relative 'year_first_date'

module Olyx
  module Guardrails
    module Pii
      # Validates year-first or ambiguous day/month numeric dates.
      module NumericDateValidator
        PARTS = %r{\A(\d{1,4})[/-](\d{1,2})[/-](\d{1,4})\z}

        module_function

        def call(value)
          parts = value.match(PARTS)&.captures
          return false unless parts

          return YearFirstDate.call(parts) if parts.first.length == 4

          AmbiguousNumericDate.call(parts)
        end
      end
    end
  end
end
