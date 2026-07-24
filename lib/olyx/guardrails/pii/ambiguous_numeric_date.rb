# frozen_string_literal: true

require 'date'

module Olyx
  module Guardrails
    module Pii
      # Accepts valid day-first or month-first numeric dates.
      module AmbiguousNumericDate
        module_function

        def call(parts)
          first, second, raw_year = parts.map(&:to_i)
          valid?(first, second, year(raw_year, parts.last))
        end

        def valid?(first, second, year)
          candidates(first, second).any? { |month, day| Date.valid_date?(year, month, day) }
        end

        def candidates(first, second)
          [[second, first], [first, second]]
        end

        def year(value, source)
          source.length == 2 ? value + 2_000 : value
        end
        private_class_method :candidates, :valid?, :year
      end
    end
  end
end
