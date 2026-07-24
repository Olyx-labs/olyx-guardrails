# frozen_string_literal: true

require_relative '../violation_labels'

module Olyx
  module Guardrails
    module Notification
      # Derives stable machine-readable violation labels from a decision.
      module ViolationLabels
        module_function

        def call(result)
          labels = Guardrails::ViolationLabels.call(result)
          labels.empty? ? ['policy_violation'] : labels
        end
      end
    end
  end
end
