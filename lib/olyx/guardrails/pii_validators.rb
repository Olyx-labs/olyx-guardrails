# frozen_string_literal: true

require_relative 'pii/iban_validator'
require_relative 'pii/date_validator'
require_relative 'pii/ipv4_validator'
require_relative 'pii/ipv6_validator'
require_relative 'pii/luhn_validator'
require_relative 'pii/ssn_validator'
require_relative 'pii/sin_validator'

module Olyx
  module Guardrails
    # Stable facade over format-specific PII validators.
    module PiiValidators
      module_function

      def luhn_valid?(value) = Pii::LuhnValidator.call(value)
      def ssn_valid?(value) = Pii::SsnValidator.call(value)
      def ipv4_valid?(value) = Pii::Ipv4Validator.call(value)
      def ipv6_valid?(value) = Pii::Ipv6Validator.call(value)
      def iban_valid?(value) = Pii::IbanValidator.call(value)
      def date_valid?(value) = Pii::DateValidator.call(value)
      def sin_valid?(value) = Pii::SinValidator.call(value)
    end
  end
end
