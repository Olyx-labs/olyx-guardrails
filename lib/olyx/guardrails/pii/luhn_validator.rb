# frozen_string_literal: true

require_relative 'luhn_checksum'

module Olyx
  module Guardrails
    module Pii
      # Validates card-like digit sequences with the Luhn checksum.
      module LuhnValidator
        MINIMUM_LENGTH = 13

        module_function

        def call(number)
          digits = LuhnChecksum.digits(number)
          digits.length >= MINIMUM_LENGTH && LuhnChecksum.valid?(digits)
        end
      end
    end
  end
end
