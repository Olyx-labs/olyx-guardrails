# frozen_string_literal: true

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Validates model identifiers without imposing a stale model allowlist.
        module ModelIdentifier
          module_function

          def call(model)
            raise ArgumentError, 'model must be a non-empty String or Symbol' unless valid?(model)

            model
          end

          def valid?(model)
            string?(model) || symbol?(model)
          end

          def string?(model) = model.is_a?(String) && !model.strip.empty?
          def symbol?(model) = model.is_a?(Symbol) && !model.to_s.empty?
          private_class_method :string?, :symbol?, :valid?
        end
      end
    end
  end
end
