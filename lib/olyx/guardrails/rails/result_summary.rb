# frozen_string_literal: true

require_relative '../violation_labels'
require_relative '../notification/deep_freezer'
require_relative 'policy_rule_names'

module Olyx
  module Guardrails
    module Rails
      # Builds the bounded decision payload used by exceptions and telemetry.
      module ResultSummary
        module_function

        def call(result)
          Notification::DeepFreezer.call(decision(result).merge(policy(result)))
        end

        def decision(result)
          {
            policy_name: result[:policy_name].to_s[0...100],
            allowed: result[:allowed] == true,
            risk_score: result[:risk_score].to_f
          }
        end

        def policy(result)
          {
            violations: Guardrails::ViolationLabels.call(result).freeze,
            policy_rules: PolicyRuleNames.call(result)
          }
        end
        private_class_method :decision, :policy
      end
    end
  end
end
