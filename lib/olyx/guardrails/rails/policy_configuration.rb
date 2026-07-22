# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Owns policy and filtering assignments during Rails boot.
      module PolicyConfiguration
        def policy=(value)
          mutable!
          @policy = ConfigurationValues.policy(value)
        end

        def policy_path=(value)
          mutable!
          @policy_path = ConfigurationValues.path(value)
        end

        def filter_parameters=(value)
          mutable!
          @filter_parameters = ConfigurationValues.filter_parameters(value)
        end
      end
    end
  end
end
