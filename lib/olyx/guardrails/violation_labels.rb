# frozen_string_literal: true

require_relative 'supplemental_violation_labels'

module Olyx
  module Guardrails
    # Derives shared machine-readable violation labels from a decision.
    module ViolationLabels
      MAPPINGS = {
        injection_attempt: 'injection_attempt',
        secret_leaked: 'secret_leaked',
        pii_detected: 'pii_detected',
        policy_violated: 'restricted_content'
      }.freeze

      module_function

      def call(result)
        labels = MAPPINGS.filter_map { |field, label| label if result[field] }
        labels.concat(SupplementalViolationLabels.call(result))
      end
    end
  end
end
