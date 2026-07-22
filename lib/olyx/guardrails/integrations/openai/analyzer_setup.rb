# frozen_string_literal: true

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Resolves analyzer dependencies and constructs its request builder.
        module AnalyzerSetup
          module_function

          def call(config, analyzer_class)
            client = config.client || analyzer_class.openai_client
            schema = config.schema || analyzer_class.analysis_schema
            resolved = ConfigurationResolver.call(config, client: client, schema: schema)
            [client, RequestBuilder.new(resolved)]
          end
        end
      end
    end
  end
end
