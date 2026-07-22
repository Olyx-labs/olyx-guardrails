# frozen_string_literal: true

module Olyx
  module Guardrails
    # Raised when framework integration cannot establish a valid, safe policy.
    class ConfigurationError < StandardError; end

    # Raised when policy requires analyzer failures to interrupt evaluation.
    class AiAnalyzerError < StandardError; end

    # Raised by explicit enforcement entry points when a policy rejects input.
    class Blocked < StandardError
      attr_reader :decision

      # @param decision [Hash] immutable, sanitized decision summary.
      def initialize(decision)
        @decision = decision
        super('input blocked by guardrail policy')
      end
    end
  end
end
