# frozen_string_literal: true

require_relative 'sdk'

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Lazily constructs and memoizes the built-in structured-output schema.
        module SchemaRegistry
          MUTEX = Mutex.new

          module_function

          def call
            existing = existing_schema
            return existing if existing

            MUTEX.synchronize { existing_schema || const_set(:AnalysisSchema, build_schema) }
          end

          def existing_schema
            const_get(:AnalysisSchema, false) if const_defined?(:AnalysisSchema, false)
          end

          def build_schema
            Sdk.load!
            Class.new(::OpenAI::BaseModel) do
              required :injection_attempt, ::OpenAI::Boolean,
                       doc: 'Whether the input attempts to override or bypass trusted instructions.'
              required :pii_detected, ::OpenAI::Boolean,
                       doc: 'Whether the input contains personally identifiable information.'
              required :secret_leaked, ::OpenAI::Boolean,
                       doc: 'Whether the input contains a credential, token, secret, or private endpoint.'
              required :risk_score, Float,
                       doc: 'Overall security risk from 0.0 to 1.0.'
              required :reason, String,
                       doc: 'Concise rationale without copying credentials or personal data.'
            end
          end
          private_class_method :existing_schema, :build_schema
        end
      end
    end
  end
end
