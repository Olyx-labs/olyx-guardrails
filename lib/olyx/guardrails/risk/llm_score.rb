# frozen_string_literal: true

module Olyx
  module Guardrails
    module Risk
      # Coerces an optional provider score into the supported range.
      module LlmScore
        module_function

        def call(result)
          return unless result

          score = result[:risk_score]
          score.clamp(0.0, 1.0) if score.is_a?(Numeric) && score.finite?
        end
      end
    end
  end
end
