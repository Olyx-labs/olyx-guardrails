# frozen_string_literal: true

module Olyx
  module Guardrails
    module Risk
      # Coerces an optional analyzer score into the supported range.
      module AiScore
        module_function

        def call(result)
          return unless result

          score = Float(result[:risk_score], exception: false)
          score.clamp(0.0, 1.0) if score&.finite?
        end
      end
    end
  end
end
