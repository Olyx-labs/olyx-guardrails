# frozen_string_literal: true

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Owns the optional dependency boundary for the official OpenAI SDK.
        module Sdk
          module_function

          def client
            load!
            ::OpenAI::Client.new
          end

          def load!
            require 'openai'
          rescue LoadError
            raise LoadError,
                  'OpenAIAnalyzer requires the optional official SDK; add gem "openai" to your Gemfile'
          end
        end
      end
    end
  end
end
