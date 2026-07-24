# frozen_string_literal: true

module Olyx
  module Guardrails
    # Builds the bounded deterministic context passed to an LLM provider.
    module LlmContextBuilder
      module_function

      def call(checks)
        detection(checks).merge(policy(checks[:policy]))
      end

      def detection(checks)
        injection = checks[:injection]
        {
          pii_detected: checks[:pii][:detected],
          injection_attempt: injection[:injection_attempt],
          injection_patterns: injection[:patterns],
          secret_leaked: checks[:secret][:leaked]
        }
      end

      def policy(check)
        {
          policy_violated: check[:violated],
          policy_rules: check[:findings].map { |finding| finding[:rule] }
        }
      end
      private_class_method :detection, :policy
    end
  end
end
