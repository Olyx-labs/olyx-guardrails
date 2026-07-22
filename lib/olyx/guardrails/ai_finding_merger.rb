# frozen_string_literal: true

require_relative 'ai/secret_finding_merger'
require_relative 'ai/flag_finding_merger'
require_relative 'ai/standard_finding_merger'

module Olyx
  module Guardrails
    # Unions semantic findings into deterministic checks without clearing any.
    class AiFindingMerger
      def self.call(checks, analysis, policy)
        new(checks, analysis, policy).call
      end

      def initialize(checks, analysis, policy)
        @checks = checks
        @analysis = analysis
        @policy = policy
      end

      def call
        @checks.merge(
          Ai::StandardFindingMerger.call(@checks, @analysis, @policy).merge(
            secret: Ai::SecretFindingMerger.call(@checks[:secret], @analysis, @policy)
          )
        )
      end
    end
  end
end
