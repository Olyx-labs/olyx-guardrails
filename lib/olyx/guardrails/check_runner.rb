# frozen_string_literal: true

require_relative 'check_result_builder'
require_relative 'check_analyzer'
require_relative 'check_set'
require_relative 'check_pipeline'
require_relative 'policy'
require_relative 'validation'

module Olyx
  module Guardrails
    # Orchestrates deterministic checks and optional semantic enrichment.
    class CheckRunner
      def self.call(input, **)
        new(input, **).call
      end

      def initialize(input, policy:, llm_provider:)
        @source = input.to_s
        @policy = policy
        @llm_provider = llm_provider
        validate_options!
      end

      def call
        checks = CheckSet.call(@source, policy: @policy)
        CheckPipeline.call(@source, checks, policy: @policy, llm_provider: @llm_provider)
      end

      private

      def validate_options!
        raise ArgumentError, 'policy must be an Olyx::Guardrails::Policy' unless @policy.is_a?(Policy)

        Validation.callable_or_nil!(@llm_provider, name: 'llm_provider')
      end
    end
  end
end
