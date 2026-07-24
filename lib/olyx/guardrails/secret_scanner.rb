# frozen_string_literal: true

require_relative 'secret_finding_collector'
require_relative 'secrets/finding_presenter'
require_relative 'secrets/redactor'
require_relative 'secrets/blocked'

module Olyx # :nodoc:
  module Guardrails
    # Detects, redacts, or rejects documented credential and internal-endpoint
    # formats.
    #
    # Public findings contain a masked value, fingerprint, category, and source
    # offsets. They never contain the complete matched credential.
    class SecretScanner
      # Raised by scan! when one or more safe secret findings exist. Instances
      # expose +findings+ and the inherited +decision+ summary.
      Blocked = Secrets::Blocked

      # :call-seq:
      #   SecretScanner.scan(text, custom_patterns: []) -> Hash
      #
      # Converts +text+ with +to_s+ and returns a +:leaked+ Boolean with safe
      # +:findings+. +custom_patterns+ must be an Array of regular-expression
      # source Strings. Invalid patterns raise ArgumentError.
      def self.scan(text, custom_patterns: [])
        findings = collect(text, custom_patterns)
        { leaked: findings.any?, findings: Secrets::FindingPresenter.call(findings) }
      end

      # :call-seq:
      #   SecretScanner.redact(text, custom_patterns: []) -> Hash
      #
      # Converts +text+ with +to_s+ and returns transformed +:text+, a +:leaked+
      # Boolean, and safe +:findings+. A confidentiality marker redacts the
      # complete input because the marker does not identify one safe span.
      def self.redact(text, custom_patterns: [])
        source = text.to_s
        findings = collect(source, custom_patterns)
        {
          text: findings.empty? ? source : Secrets::Redactor.call(source, findings),
          leaked: findings.any?,
          findings: Secrets::FindingPresenter.call(findings)
        }
      end

      # :call-seq:
      #   SecretScanner.scan!(text, custom_patterns: []) -> Hash
      #
      # Returns the same result as scan when no finding exists. Raises
      # SecretScanner::Blocked with safe findings when a secret is detected.
      def self.scan!(text, custom_patterns: [])
        result = scan(text, custom_patterns: custom_patterns)
        raise Blocked, result[:findings] if result[:leaked]

        result
      end

      def self.collect(text, custom_patterns)
        SecretFindingCollector.call(text.to_s, custom_patterns: custom_patterns)
      end
      private_class_method :collect
    end
  end
end
