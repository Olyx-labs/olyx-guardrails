# frozen_string_literal: true

require 'date'

module Olyx
  module Guardrails
    module Pii
      # Validates numeric dates whose first component is a four-digit year.
      module YearFirstDate
        module_function

        def call(parts)
          Date.valid_date?(*parts.map(&:to_i))
        end
      end
    end
  end
end
