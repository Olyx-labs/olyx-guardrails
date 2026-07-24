# frozen_string_literal: true

require_relative 'check_weights'

module Olyx
  module Guardrails
    module Risk
      # Computes the bounded score contributed by deterministic checks.
      module DeterministicScore
        module_function

        def call(checks, ordered_checks)
          score = CheckWeights.call(checks)
          score += BLOCKED_RISK_WEIGHT if ordered_checks.any? { |check| !check[:allowed] }
          score.clamp(0.0, 1.0).round(4)
        end
      end
    end
  end
end
