# frozen_string_literal: true

module Olyx
  module Guardrails
    # Applies the policy-selected behavior for an analyzer failure.
    module AiFailureHandler
      module_function

      def call(checks, analysis, mode)
        return checks if mode == :allow
        raise AiAnalyzerError, analysis[:error] if mode == :raise

        checks.merge(ai: { type: 'ai', allowed: false, error: true })
      end
    end
  end
end
