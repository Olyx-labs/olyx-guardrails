# frozen_string_literal: true

require_relative 'policy_rule/configuration'

module Olyx
  module Guardrails
    # Immutable named restricted-content rule.
    class PolicyRule
      def initialize(name:, patterns: [], terms: [], match: :substring, block: true, description: nil, replacement: nil)
        @identity = PolicyRuleComponents::IdentityConfiguration.new(name, description)
        @matching = PolicyRuleComponents::MatchConfiguration.new(patterns, terms, match)
        @enforcement = PolicyRuleComponents::EnforcementConfiguration.new(block, replacement || default_replacement)
        freeze
      end

      def name = @identity.name
      def description = @identity.description
      def match = @matching.mode
      def patterns = @matching.patterns
      def replacement = @enforcement.replacement
      def block? = @enforcement.block?

      private

      def default_replacement
        "[RESTRICTED:#{@identity.name.upcase}]"
      end
    end
  end
end
