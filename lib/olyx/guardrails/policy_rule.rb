# frozen_string_literal: true

require_relative 'policy_rule/configuration'

module Olyx # :nodoc:
  module Guardrails
    # Defines one immutable, named restricted-content rule.
    #
    # Rules may contain escaped terms, regular expressions, or both. Matching
    # records safe fingerprints and offsets; it does not expose the matched
    # restricted text in public findings.
    class PolicyRule
      # :call-seq:
      #   PolicyRule.new(name:, patterns: [], terms: [], match: :substring,
      #                  block: true, description: nil, replacement: nil)
      #
      # Builds and freezes a rule.
      #
      # +name+ is the stable rule identifier. +terms+ contains non-empty
      # Strings. +patterns+ contains Regexp objects or regular-expression source
      # Strings. +match+ controls how terms compile and accepts +:substring+,
      # +:whole_word+, or +:regexp+.
      #
      # +block+ controls the decision but not redaction. +description+ is
      # optional safe metadata. +replacement+ is the text used during
      # redaction; when omitted it is derived from +name+.
      #
      # Invalid values and expressions that match empty text raise
      # ArgumentError.
      def initialize(name:, patterns: [], terms: [], match: :substring, block: true, description: nil, replacement: nil)
        @identity = PolicyRuleComponents::IdentityConfiguration.new(name, description)
        @matching = PolicyRuleComponents::MatchConfiguration.new(patterns, terms, match)
        @enforcement = PolicyRuleComponents::EnforcementConfiguration.new(block, replacement || default_replacement)
        freeze
      end

      # Returns the normalized String rule identifier.
      def name = @identity.name

      # Returns the optional description, or +nil+.
      def description = @identity.description

      # Returns +:substring+, +:whole_word+, or +:regexp+.
      def match = @matching.mode

      # Returns the frozen compiled Regexp collection.
      def patterns = @matching.patterns

      # Returns the safe replacement used by redaction.
      def replacement = @enforcement.replacement

      # Returns whether a match blocks a decision.
      def block? = @enforcement.block?

      private

      def default_replacement
        "[RESTRICTED:#{@identity.name.upcase}]"
      end
    end
  end
end
