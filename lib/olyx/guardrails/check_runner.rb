# frozen_string_literal: true

require_relative 'ai_analysis'
require_relative 'ai_context_builder'
require_relative 'ai_finding_merger'
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

      def initialize(input, policy:, ai_analyzer:)
        @source = input.to_s
        @policy = policy
        @ai_analyzer = ai_analyzer
        validate_options!
      end

      def call
        checks = CheckSet.call(@source, policy: @policy)
        CheckPipeline.call(@source, checks, policy: @policy, ai_analyzer: @ai_analyzer)
      end

      private

      def validate_options!
        raise ArgumentError, 'policy must be an Olyx::Guardrails::Policy' unless @policy.is_a?(Policy)

        Validation.callable_or_nil!(@ai_analyzer, name: 'ai_analyzer')
      end
    end
  end
end
