# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyComponents
      # Presents policy matches and their redacted output.
      module RedactionResult
        module_function

        def call(source, findings, transform)
          {
            text: PolicyRedactor.call(source, findings, transform: transform),
            violated: findings.any?,
            findings: FindingPresenter.call(findings)
          }
        end
      end
    end
  end
end
