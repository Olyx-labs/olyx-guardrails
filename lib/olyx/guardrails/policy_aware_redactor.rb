# frozen_string_literal: true

require_relative 'pii_scrubber'
require_relative 'policy_scanner'
require_relative 'secret_scanner'
require_relative 'redaction/content_result'
require_relative 'redaction/unrestricted_text'

module Olyx
  # Guardrail policy types and evaluation services.
  module Guardrails
    # Produces one policy-aware redaction result while preserving findings from
    # the original source. Policy spans take precedence over narrower scanner
    # substitutions; confidentiality markers remain fail-closed.
    class PolicyAwareRedactor
      def self.call(source, policy:)
        new(source, policy).call
      end

      def initialize(source, policy)
        @source = source.to_s
        @policy = policy
      end

      def call
        secret_scan = SecretScanner.scan(
          @source,
          custom_patterns: @policy.secret_patterns
        )
        policy_redaction = PolicyScanner.redact(@source, policy: @policy) do |text|
          Redaction::UnrestrictedText.call(text, @policy)
        end

        Redaction::ContentResult.call(
          @source, text: policy_redaction[:text], secret_scan: secret_scan, policy_redaction: policy_redaction
        )
      end
    end

    private_constant :PolicyAwareRedactor
  end
end
