# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyComponents
      # Presents policy matches as a scan decision.
      module ScanResult
        module_function

        def call(findings)
          violated = findings.any?
          {
            violated: violated,
            blocked: violated && findings.any? { |finding| finding[:rule].block? },
            findings: FindingPresenter.call(findings)
          }
        end
      end
    end
  end
end
