# frozen_string_literal: true

module Olyx
  module Guardrails
    module Notification
      # Builds the required vendor-neutral notification fields.
      module BaseEvent
        module_function

        def call(result, metadata:, policy:, sanitizer:, schema_version:)
          decision(result, schema_version).merge(context(result, metadata, policy, sanitizer))
        end

        def decision(result, schema_version)
          {
            schema_version: schema_version,
            event: 'guardrail.violation',
            allowed: result[:allowed] == true,
            risk_score: result[:risk_score].to_f,
            violations: ViolationLabels.call(result)
          }
        end

        def context(result, metadata, policy, sanitizer)
          {
            policy_name: sanitizer.field(policy.name, max_length: 100),
            policy_rule_count: Array(result[:policy_findings]).length,
            metadata: Metadata.call(metadata, sanitizer)
          }
        end
        private_class_method :context, :decision
      end
    end
  end
end
