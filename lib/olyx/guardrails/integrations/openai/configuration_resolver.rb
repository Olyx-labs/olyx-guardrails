# frozen_string_literal: true

require_relative '../openai_analyzer_configuration'

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Resolves optional client and schema dependencies after validation.
        module ConfigurationResolver
          module_function

          def call(config, client:, schema:)
            OpenAIAnalyzerConfiguration.new(
              model: config.model,
              client: client,
              schema: config.schema || schema,
              instructions: config.instructions,
              store: config.store,
              request_options: config.request_options,
              response_options: config.response_options
            )
          end
        end
      end
    end
  end
end
