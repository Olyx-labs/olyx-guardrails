# frozen_string_literal: true

module Olyx
  module Guardrails
    # Applies the policy-selected behavior for an LLM provider failure.
    module LlmFailureHandler
      module_function

      def call(checks, analysis, mode)
        return checks if mode == :allow
        raise LlmProviderError, analysis[:error] if mode == :raise

        checks.merge(llm: { type: 'llm', allowed: false, error: true })
      end
    end
  end
end
