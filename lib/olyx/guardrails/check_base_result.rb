# frozen_string_literal: true

module Olyx
  module Guardrails
    # Builds the stable deterministic portion of a check decision.
    module CheckBaseResult
      module_function

      def call(checks, ordered, policy)
        detection(checks, ordered).merge(policy(checks[:policy], policy))
      end

      def detection(checks, ordered)
        {
          allowed: ordered.all? { |check| check[:allowed] },
          pii_detected: checks[:pii][:detected],
          injection_attempt: checks[:injection][:injection_attempt],
          secret_leaked: checks[:secret][:leaked]
        }
      end

      def policy(check, configuration)
        {
          policy_name: configuration.name,
          policy_violated: check[:violated],
          policy_findings: check[:findings]
        }
      end
      private_class_method :detection, :policy
    end
  end
end
