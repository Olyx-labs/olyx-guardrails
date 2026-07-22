# frozen_string_literal: true

module Olyx
  module Guardrails
    module Ai
      # Merges semantic PII and injection flags using declarative mappings.
      module StandardFindingMerger
        SETTINGS = {
          pii: %i[pii_detected detected block_pii?],
          injection: %i[injection_attempt injection_attempt block_injections?]
        }.freeze

        module_function

        def call(checks, analysis, policy)
          SETTINGS.to_h do |check_name, (finding_name, result_name, blocking_query)|
            changes = { result_name => true, allowed: !policy.public_send(blocking_query) }
            [check_name, FlagFindingMerger.call(checks[check_name], analysis[finding_name], changes)]
          end
        end
      end
    end
  end
end
