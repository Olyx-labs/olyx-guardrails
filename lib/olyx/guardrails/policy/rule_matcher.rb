# frozen_string_literal: true

require_relative 'pattern_matcher'
require_relative 'normalized_pattern_matcher'

module Olyx
  module Guardrails
    module PolicyComponents
      # Collects original and normalized matches for one policy rule.
      module RuleMatcher
        TIMEOUT_ERROR = defined?(Regexp::TimeoutError) ? Regexp::TimeoutError : RegexpError

        module_function

        def call(source, rule, index)
          rule.patterns.flat_map { |pattern| matches(source, rule, index, pattern) }
        rescue TIMEOUT_ERROR
          raise ArgumentError, "policy rule #{rule.name.inspect} timed out"
        end

        def matches(source, rule, index, pattern)
          PatternMatcher.call(source, rule, index, pattern) +
            NormalizedPatternMatcher.call(source, rule, index, pattern)
        end
        private_class_method :matches
      end
    end
  end
end
