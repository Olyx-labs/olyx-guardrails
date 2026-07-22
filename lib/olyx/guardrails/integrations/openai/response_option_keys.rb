# frozen_string_literal: true

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Rejects invalid or connector-owned response option keys.
        module ResponseOptionKeys
          RESERVED = %i[model input text store request_options].freeze

          module_function

          def validate!(keys)
            validate_types!(keys)
            validate_reserved!(keys)
          end

          def validate_types!(keys)
            valid = keys.all? { |key| key.is_a?(String) || key.is_a?(Symbol) }
            raise ArgumentError, 'response_options keys must be Strings or Symbols' unless valid
          end

          def validate_reserved!(keys)
            reserved = keys.map(&:to_sym) & RESERVED
            raise ArgumentError, "response_options cannot override: #{reserved.join(', ')}" unless reserved.empty?
          end
          private_class_method :validate_reserved!, :validate_types!
        end
      end
    end
  end
end
