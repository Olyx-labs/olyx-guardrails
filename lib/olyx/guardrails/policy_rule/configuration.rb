# frozen_string_literal: true

require_relative '../enum_value'
require_relative 'pattern_compiler'
require_relative 'values'

module Olyx
  module Guardrails
    module PolicyRuleComponents
      MATCH_MODE = EnumValue.new(
        allowed: %i[substring whole_word regexp],
        error: 'policy rule match must be substring, whole_word, or regexp'
      )
      private_constant :MATCH_MODE

      # Validated identity and descriptive policy-rule fields.
      class IdentityConfiguration
        attr_reader :name, :description

        def initialize(name, description)
          @name = Values.name(name)
          @description = Values.description(description)
          freeze
        end
      end

      # Validated policy-rule matching configuration.
      class MatchConfiguration
        attr_reader :mode, :patterns

        def initialize(patterns, terms, match)
          @mode = MATCH_MODE.call(match)
          @patterns = PatternCompiler.call(patterns: patterns, terms: terms, match: @mode)
          freeze
        end
      end

      # Validated policy-rule enforcement behavior.
      class EnforcementConfiguration
        attr_reader :replacement

        def initialize(block, replacement)
          @block = Values.boolean(block)
          @replacement = Values.replacement(replacement)
          freeze
        end

        def block? = @block
      end
    end
  end
end
