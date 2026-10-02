# frozen_string_literal: true

require_relative 'policy_rule/pattern_compiler'
require_relative 'validation'

module Olyx # :nodoc:
  module Guardrails
    # Defines one immutable, named restricted-content rule.
    #
    # Rules may contain escaped terms, regular expressions, or both. Matching
    # records safe fingerprints and offsets; it does not expose the matched
    # restricted text in public findings.
    class PolicyRule
      MATCH_MODES = %i[substring whole_word regexp].freeze
      NAME_FORMAT = /\A[a-z][a-z0-9_.:-]*\z/i
      private_constant :MATCH_MODES, :NAME_FORMAT

      # Returns the normalized String rule identifier.
      attr_reader :name

      # Returns the optional description, or +nil+.
      attr_reader :description

      # Returns +:substring+, +:whole_word+, or +:regexp+.
      attr_reader :match

      # Returns the frozen compiled Regexp collection.
      attr_reader :patterns

      # Returns the safe replacement used by redaction.
      attr_reader :replacement

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
        @name = validate_name(name)
        @description = validate_description(description)
        @match = validate_match(match)
        @patterns = PolicyRuleComponents::PatternCompiler.call(patterns: patterns, terms: terms, match: @match)
        @block = Validation.boolean!(block, name: 'policy rule block')
        @replacement = validate_replacement(replacement || default_replacement)
        freeze
      end

      # Returns whether a match blocks a decision.
      def block? = @block

      private

      def default_replacement
        "[RESTRICTED:#{@name.upcase}]"
      end

      def validate_name(value)
        normalized = value.to_s
        valid = (value.is_a?(String) || value.is_a?(Symbol)) && normalized.match?(NAME_FORMAT)
        raise ArgumentError, 'policy rule name must be a String or Symbol identifier' unless valid

        normalized.dup.freeze
      end

      def validate_match(value)
        normalized = value.respond_to?(:to_sym) ? value.to_sym : value
        return normalized if MATCH_MODES.include?(normalized)

        raise ArgumentError, 'policy rule match must be substring, whole_word, or regexp'
      end

      def validate_description(value)
        return nil if value.nil?
        return value.dup.freeze if value.is_a?(String) && !value.strip.empty? && value.length <= 500

        raise ArgumentError, 'policy rule description must be a String of 1..500 characters or nil'
      end

      def validate_replacement(value)
        valid = value.is_a?(String) && !value.empty? && value.length <= 100 && !value.match?(/[\r\n\t]/)
        raise ArgumentError, 'policy rule replacement must be a single-line String of 1..100 characters' unless valid

        value.dup.freeze
      end
    end
  end
end
