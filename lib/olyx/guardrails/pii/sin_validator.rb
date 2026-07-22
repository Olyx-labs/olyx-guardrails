# frozen_string_literal: true

require_relative 'luhn_checksum'

module Olyx
  module Guardrails
    module Pii
      # Validates Canadian Social Insurance Numbers with the same Luhn
      # checksum as card numbers, but at SIN's fixed 9-digit length —
      # {LuhnValidator} enforces its own 13-digit floor for card use, so this
      # applies SIN's length rule against the shared {LuhnChecksum} directly.
      module SinValidator
        LENGTH = 9

        module_function

        def call(sin)
          digits = LuhnChecksum.digits(sin)
          digits.length == LENGTH && LuhnChecksum.valid?(digits)
        end
      end
    end
  end
end
