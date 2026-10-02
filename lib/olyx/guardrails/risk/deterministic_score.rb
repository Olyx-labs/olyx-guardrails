# frozen_string_literal: true

require_relative 'check_weights'

module Olyx
  module Guardrails
    module Risk
      # Computes the bounded score contributed by deterministic checks.
      module DeterministicScore
        module_function

        def call(checks)
          CheckWeights.call(checks).clamp(0.0, 1.0).round(4)
        end
      end
    end
  end
end
