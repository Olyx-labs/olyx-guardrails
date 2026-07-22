# frozen_string_literal: true

require_relative 'response_options'
require_relative 'request_values'

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Validates options that control a Responses API request.
        class RequestConfiguration
          attr_reader :instructions, :store, :request_options, :response_options

          def initialize(instructions:, store:, request_options:, response_options:)
            @instructions = RequestValues.instructions(instructions)
            @store = RequestValues.store(store)
            @request_options = RequestValues.request_options(request_options)
            @response_options = ResponseOptions.call(response_options)
            freeze
          end
        end
      end
    end
  end
end
