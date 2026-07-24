# frozen_string_literal: true

module Olyx
  module Guardrails
    module Risk
      # Owns the deterministic risk model shared by scoring and the public API.
      module Weights
        FINDINGS = {
          injection: [:injection_attempt, 0.50],
          secret: [:leaked, 0.25],
          pii: [:detected, 0.10],
          policy: [:violated, 0.25]
        }.freeze
        BLOCKED = 0.15
      end
    end
  end
end
