# frozen_string_literal: true

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Validates scalar Responses API request settings.
        module RequestValues
          module_function

          def instructions(value)
            valid = value.is_a?(String) && !value.strip.empty?
            raise ArgumentError, 'instructions must be a non-empty String' unless valid

            value
          end

          def store(value)
            raise ArgumentError, 'store must be true or false' unless [true, false].include?(value)

            value
          end

          def request_options(value)
            raise ArgumentError, 'request_options must be a Hash or nil' unless value.nil? || value.is_a?(Hash)

            value
          end
        end
      end
    end
  end
end
