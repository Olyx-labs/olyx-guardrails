# frozen_string_literal: true

module Olyx
  module Guardrails
    module Redaction
      # Builds the stable internal redaction content contract.
      module ContentResult
        module_function

        def call(source, text:, secret_scan:, policy_redaction:)
          findings = secret_scan[:findings]
          detection(source, secret_scan, policy_redaction).merge(content(text, findings))
        end

        def content(text, findings)
          output = '[REDACTED]' if findings.any? { |finding| finding[:category] == 'confidentiality_marker' }
          { text: output || text, findings: findings }
        end

        def detection(source, secret_scan, policy_redaction)
          {
            pii_detected: PiiScrubber.scrub(source) != source,
            secret_leaked: secret_scan[:leaked],
            policy_violated: policy_redaction[:violated],
            policy_findings: policy_redaction[:findings]
          }
        end
        private_class_method :content, :detection
      end
    end
  end
end
