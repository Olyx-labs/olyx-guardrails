# frozen_string_literal: true

require_relative 'secret_finding_collector'
require_relative 'secrets/finding_presenter'
require_relative 'secrets/redactor'
require_relative 'secrets/blocked'

module Olyx
  module Guardrails
    # Public detect, redact, and exception-driven secret operations.
    class SecretScanner
      Blocked = Secrets::Blocked

      def self.scan(text, custom_patterns: [])
        findings = collect(text, custom_patterns)
        { leaked: findings.any?, findings: Secrets::FindingPresenter.call(findings) }
      end

      def self.redact(text, custom_patterns: [])
        source = text.to_s
        findings = collect(source, custom_patterns)
        {
          text: findings.empty? ? source : Secrets::Redactor.call(source, findings),
          leaked: findings.any?,
          findings: Secrets::FindingPresenter.call(findings)
        }
      end

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
