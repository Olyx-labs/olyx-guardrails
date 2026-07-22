# frozen_string_literal: true

require_relative 'input_builder'

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Builds the owned and caller-supplied Responses API parameters.
        class RequestBuilder
          def initialize(configuration)
            @configuration = configuration
          end

          def call(text, context)
            params = @configuration.response_options.merge(owned_params(text, context))
            request_options = @configuration.request_options
            params[:request_options] = request_options if request_options
            params
          end

          private

          def owned_params(text, context)
            {
              model: @configuration.model,
              input: InputBuilder.call(text, context, instructions: @configuration.instructions),
              text: @configuration.schema,
              store: @configuration.store
            }
          end
        end
      end
    end
  end
end
