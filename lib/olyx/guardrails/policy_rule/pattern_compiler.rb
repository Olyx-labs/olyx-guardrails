# frozen_string_literal: true

require_relative 'regexp_compiler'
require_relative 'term_compiler'

module Olyx
  module Guardrails
    module PolicyRuleComponents
      # Compiles bounded policy regexes and rejects empty matching patterns.
      module PatternCompiler
        module_function

        def call(patterns:, terms:, match:)
          validate_collections!(patterns, terms)
          compiled = patterns.map { |value| RegexpCompiler.call(value) }
          compiled.concat(terms.map { |term| TermCompiler.call(term, mode: match) }).freeze
        end

        def validate_collections!(patterns, terms)
          valid = patterns.is_a?(Array) && terms.is_a?(Array) && !(patterns.empty? && terms.empty?)
          raise ArgumentError, 'policy rule patterns or terms must be a non-empty Array' unless valid
        end

        private_class_method :validate_collections!
      end
    end
  end
end
