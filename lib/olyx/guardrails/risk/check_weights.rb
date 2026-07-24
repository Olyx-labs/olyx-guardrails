# frozen_string_literal: true

require_relative 'weights'

module Olyx
  module Guardrails
    module Risk
      # Sums risk weights for positive deterministic findings.
      module CheckWeights
        module_function

        def call(checks)
          Weights::FINDINGS.sum { |check, (finding, weight)| checks[check][finding] ? weight : 0.0 }
        end
      end
    end
  end
end
