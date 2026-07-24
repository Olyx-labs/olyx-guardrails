# frozen_string_literal: true

require 'digest'

module Olyx
  module Guardrails
    module Secrets
      # Converts private findings into safe correlation records.
      module FindingPresenter
        module_function

        def call(findings)
          findings.map { |finding| present(finding) }
        end

        def present(finding)
          value = finding[:full]
          {
            category: finding[:category],
            matched: mask(value),
            fingerprint: "sha256:#{Digest::SHA256.hexdigest(value)[0, 12]}",
            start: finding[:start],
            end: finding[:end]
          }
        end

        def mask(value)
          value.length < 12 ? '[REDACTED]' : "#{value[0, 4]}…#{value[-4, 4]}"
        end
        private_class_method :present, :mask
      end
    end
  end
end
