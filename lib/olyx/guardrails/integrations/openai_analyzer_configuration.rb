# frozen_string_literal: true

require_relative 'openai/dependency_contracts'
require_relative 'openai/model_identifier'
require_relative 'openai/request_configuration'

module Olyx
  module Guardrails
    module Integrations
      # Validated, immutable request configuration used by {OpenAIAnalyzer}.
      # Kept separate from transport behavior so invalid integration settings
      # fail before a client request can be constructed.
      class OpenAIAnalyzerConfiguration
        attr_reader :model, :client, :schema

        def initialize(
          model:, client:, schema:, instructions:, store:, request_options:, response_options:
        )
          @request = OpenAIComponents::RequestConfiguration.new(
            instructions: instructions,
            store: store,
            request_options: request_options,
            response_options: response_options
          )
          @model = OpenAIComponents::ModelIdentifier.call(model)
          @client = OpenAIComponents::DependencyContracts.client(client)
          @schema = OpenAIComponents::DependencyContracts.schema(schema)
          freeze
        end

        def instructions = @request.instructions
        def store = @request.store
        def request_options = @request.request_options
        def response_options = @request.response_options
      end
    end
  end
end
