# frozen_string_literal: true

module Olyx
  module Guardrails
    module Secrets
      # Deduplicates and orders secret findings by private offsets and category.
      module FindingOrder
        module_function

        def call(findings)
          key = ->(finding) { [finding[:start], finding[:end], finding[:category]] }
          findings.uniq(&key).sort_by(&key)
        end
      end
    end
  end
end
