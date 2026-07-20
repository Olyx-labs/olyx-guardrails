# frozen_string_literal: true

module Olyx
  module Guardrails
    # Structural validators used to reject false-positive PII candidates.
    module PiiValidators
      module_function

      # Luhn validation for card-like digit sequences.
      def luhn_valid?(number)
        digits = number.gsub(/\D/, "").chars.map(&:to_i)
        return false if digits.length < 13

        sum = digits.reverse.each_with_index.sum do |digit, index|
          next digit if index.even?

          doubled = digit * 2
          doubled > 9 ? doubled - 9 : doubled
        end
        (sum % 10).zero?
      end

      # Rejects structurally impossible U.S. SSNs.
      def ssn_valid?(ssn)
        area, group, serial = ssn.split(/[- ]/)
        return false unless area && group && serial

        !area.match?(/\A(?:000|666|9\d{2})\z/) && group != "00" && serial != "0000"
      end

      # Validates every IPv4 octet.
      def ipv4_valid?(address)
        octets = address.split(".")
        octets.length == 4 && octets.all? { |octet| octet.to_i.between?(0, 255) }
      end

      # ISO 13616 mod-97 validation for IBAN candidates.
      def iban_valid?(iban)
        compact = iban.delete(" ").upcase
        return false unless compact.match?(/\A[A-Z]{2}\d{2}[A-Z0-9]{11,30}\z/)
        return false unless compact.length.between?(15, 34)

        rearranged = compact[4..] + compact[0, 4]
        rearranged.each_char.reduce(0) { |value, char| iban_remainder(value, char) } == 1
      end

      def iban_remainder(remainder, char)
        iban_digits(char).each_char.reduce(remainder) do |value, digit|
          ((value * 10) + digit.to_i) % 97
        end
      end
      private_class_method :iban_remainder

      def iban_digits(char)
        char.match?(/[A-Z]/) ? (char.ord - 55).to_s : char
      end
      private_class_method :iban_digits
    end
  end
end
