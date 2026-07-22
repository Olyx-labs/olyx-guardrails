# frozen_string_literal: true

require 'digest'

module Olyx
  module Guardrails
    module PolicyComponents
      # Converts private policy matches to masked public findings.
      module FindingPresenter
        module_function

        def call(findings)
          findings.map { |finding| present(finding) }
        end

        def present(finding)
          rule = finding[:rule]
          identity(rule, finding).merge(location(finding)).compact
        end

        def identity(rule, finding)
          {
            rule: rule.name,
            description: rule.description,
            blocked: rule.block?,
            matched: '[REDACTED]',
            fingerprint: "sha256:#{Digest::SHA256.hexdigest(finding[:full])[0, 12]}"
          }
        end

        def location(finding)
          {
            start: finding[:start],
            end: finding[:end]
          }
        end
        private_class_method :identity, :location, :present
      end
    end
  end
end
