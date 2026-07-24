# frozen_string_literal: true

require_relative 'policy/match_collector'
require_relative 'policy/redaction_result'
require_relative 'policy/scan_result'

module Olyx
  # Policy-driven safety checks and redaction for Ruby applications.
  module Guardrails
    # Presents restricted-content decisions while keeping matched text private.
    class PolicyScanner
      def self.scan(text, policy:)
        new(text, policy).scan
      end

      def self.redact(text, policy:, &transform)
        new(text, policy).redact(&transform)
      end

      def initialize(text, policy)
        @source = text.to_s
        @policy = policy
      end

      def scan
        PolicyComponents::ScanResult.call(raw_findings)
      end

      def redact(&transform)
        PolicyComponents::RedactionResult.call(@source, raw_findings, transform)
      end

      private

      def raw_findings
        PolicyComponents::MatchCollector.call(@source, @policy.rules)
      end
    end

    private_constant :PolicyScanner
  end
end
