# frozen_string_literal: true

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Reduces deterministic scanner context to the OpenAI prompt contract.
        module SignalSummary
          module_function

          def call(signals)
            privacy(signals).merge(injection(signals), policy(signals))
          end

          def privacy(signals)
            {
              pii_detected: signals[:pii_detected] == true,
              secret_leaked: signals[:secret_leaked] == true
            }
          end

          def injection(signals)
            {
              injection_attempt: signals[:injection_attempt] == true,
              injection_pattern_count: Array(signals[:injection_patterns]).length
            }
          end

          def policy(signals)
            {
              policy_violated: signals[:policy_violated] == true,
              policy_rules: Array(signals[:policy_rules]).map(&:to_s)
            }
          end
          private_class_method :injection, :policy, :privacy
        end
      end
    end
  end
end
