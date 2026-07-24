# frozen_string_literal: true

module Olyx
  module Guardrails
    module Pii
      # Shared Luhn digit-parsing and checksum validity, reused by every
      # format that applies the Luhn algorithm at its own fixed or minimum
      # length (cards, Canadian SIN) so that length rule is the only thing
      # each caller needs to own.
      module LuhnChecksum
        module_function

        def digits(number) = number.gsub(/\D/, '').chars.map(&:to_i)

        def valid?(digits) = (checksum(digits) % 10).zero?

        def checksum(digits)
          digits.reverse.each_with_index.sum { |digit, index| index.even? ? digit : doubled(digit) }
        end

        def doubled(digit)
          value = digit * 2
          value > 9 ? value - 9 : value
        end
        private_class_method :doubled
      end
    end
  end
end
