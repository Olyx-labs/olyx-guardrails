# frozen_string_literal: true

require_relative 'policy'
require_relative 'policy_aware_redactor'
require_relative 'redaction/input_validator'
require_relative 'redaction/public_result'

module Olyx
  module Guardrails
    # Applies the PII, secret, and restricted-policy transformation used by
    # Olyx::Guardrails.redact.
    class Redactor
      def self.call(input, policy:)
        new(input, policy).call
      end

      def initialize(input, policy)
        @source = input.to_s
        @policy = policy
      end

      def call
        Redaction::InputValidator.call(@source, @policy)
        content = PolicyAwareRedactor.call(@source, policy: @policy)
        Redaction::PublicResult.call(@source, content, @policy)
      end
    end
  end
end
