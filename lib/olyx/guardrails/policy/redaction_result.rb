# frozen_string_literal: true

require_relative 'finding_presenter'
require_relative 'redaction_spans'
require_relative 'unmatched_transformer'

module Olyx
  module Guardrails
    module PolicyComponents
      # Presents policy matches and their redacted output.
      module RedactionResult
        module_function

        def call(source, findings, transform)
          {
            text: UnmatchedTransformer.call(source, RedactionSpans.call(findings), transform),
            violated: findings.any?,
            findings: FindingPresenter.call(findings)
          }
        end
      end
    end
  end
end
