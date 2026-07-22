# frozen_string_literal: true

require 'date'
require_relative 'named_date_validator'
require_relative 'numeric_date_validator'

module Olyx
  module Guardrails
    module Pii
      # Validates labeled date-of-birth candidates as real calendar dates.
      module DateValidator
        DATE = %r{(?:\d{1,4}[/-]\d{1,2}[/-]\d{1,4}|[A-Za-z]+\.?\s+\d{1,2},?\s+\d{4})}

        module_function

        def call(value)
          candidate = value[DATE]
          return false unless candidate

          candidate.match?(/\A\d/) ? NumericDateValidator.call(candidate) : NamedDateValidator.call(candidate)
        end
      end
    end
  end
end
