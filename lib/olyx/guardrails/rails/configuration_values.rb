# frozen_string_literal: true

require_relative '../policy'
require_relative 'filter_parameters'
require_relative 'path_value'

module Olyx
  module Guardrails
    module Rails
      # Normalizes individual Rails configuration values before boot freezes.
      module ConfigurationValues
        module_function

        def policy(value)
          return value if value.is_a?(Policy)

          raise ArgumentError, 'Rails policy must be an Olyx::Guardrails::Policy'
        end

        def path(value)
          PathValue.call(value)
        end

        def filter_parameters(value)
          FilterParameters.call(value)
        end
      end
    end
  end
end
