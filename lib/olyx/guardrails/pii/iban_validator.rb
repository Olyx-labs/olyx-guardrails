# frozen_string_literal: true

require_relative 'iban_remainder'

module Olyx
  module Guardrails
    module Pii
      # Applies ISO 13616 mod-97 validation to IBAN candidates.
      module IbanValidator
        FORMAT = /\A[A-Z]{2}\d{2}[A-Z0-9]{11,30}\z/

        module_function

        def call(iban)
          compact = compact(iban)
          return false unless valid_format?(compact)

          valid_checksum?(compact)
        end

        def compact(iban) = iban.delete(' ').upcase

        def valid_format?(compact)
          compact.length.between?(15, 34) && compact.match?(FORMAT)
        end

        def valid_checksum?(compact)
          IbanRemainder.call(compact[4..] + compact[0, 4]) == 1
        end
        private_class_method :compact, :valid_checksum?, :valid_format?
      end
    end
  end
end
