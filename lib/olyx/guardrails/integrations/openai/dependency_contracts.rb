# frozen_string_literal: true

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Validates injected SDK collaborators at the integration boundary.
        module DependencyContracts
          module_function

          def client(value)
            raise ArgumentError, 'client must expose responses' unless value.nil? || value.respond_to?(:responses)

            value
          end

          def schema(value)
            unless value.nil? || value.respond_to?(:to_json_schema)
              raise ArgumentError, 'schema must be an OpenAI schema model class'
            end

            value
          end
        end
      end
    end
  end
end
