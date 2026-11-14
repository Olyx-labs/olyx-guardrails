# frozen_string_literal: true

require 'date'

module Olyx
  module Guardrails
    module Pii
      # Validates year-first and ambiguous day/month dates without guessing a locale.
      module NumericDateValidator
        PARTS = %r{\A(\d{1,4})[/-](\d{1,2})[/-](\d{1,4})\z}

        module_function

        def call(value)
          parts = value.match(PARTS)&.captures
          return false unless parts
          return Date.valid_date?(*parts.map(&:to_i)) if parts.first.length == 4

          ambiguous_date?(parts)
        end

        def ambiguous_date?(parts)
          first, second, year = parts.map(&:to_i)
          year += 2_000 if parts.last.length == 2
          Date.valid_date?(year, second, first) || Date.valid_date?(year, first, second)
        end
        private_class_method :ambiguous_date?
      end
    end
  end
end
