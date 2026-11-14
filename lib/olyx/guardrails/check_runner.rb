# frozen_string_literal: true

require_relative 'check_result_builder'
require_relative 'check_analyzer'
require_relative 'check_set'
require_relative 'policy'
require_relative 'validation'
require_relative 'message_source'

module Olyx
  module Guardrails
    # Orchestrates deterministic checks and optional semantic enrichment.
    class CheckRunner
      def self.call(input, **)
        new(input, **).call
      end

      def initialize(input, policy:, llm_provider:, structured: false)
        Validation.array_of!(input, Hash, name: 'messages') if structured
        @messages = input if structured
        @source = input.to_s unless structured
        @policy = policy
        @llm_provider = llm_provider
        validate_options!
        @source = MessageSource.call(input) if structured
      end

      def call
        checks = CheckSet.call(@source, policy: @policy, messages: @messages)
        merged, analysis = CheckAnalyzer.call(
          checks, provider: @llm_provider, source: @source, policy: @policy
        )
        CheckResultBuilder.call(merged, analysis, @policy)
      end

      private

      def validate_options!
        raise ArgumentError, 'policy must be an Olyx::Guardrails::Policy' unless @policy.is_a?(Policy)

        Validation.callable_or_nil!(@llm_provider, name: 'llm_provider')
      end
    end
  end
end
