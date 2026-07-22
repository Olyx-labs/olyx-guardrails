# frozen_string_literal: true

require_relative 'response_option_keys'

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Normalizes additional API options while protecting owned parameters.
        module ResponseOptions
          module_function

          def call(options)
            raise ArgumentError, 'response_options must be a Hash' unless options.is_a?(Hash)

            ResponseOptionKeys.validate!(options.keys)
            options.to_h { |key, value| [key.to_sym, value] }.freeze
          end
        end
      end
    end
  end
end
