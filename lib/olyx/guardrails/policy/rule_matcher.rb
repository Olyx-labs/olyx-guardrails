# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyComponents
      # Collects original and normalized matches for one policy rule.
      module RuleMatcher
        TIMEOUT_ERROR = defined?(Regexp::TimeoutError) ? Regexp::TimeoutError : RegexpError

        module_function

        def call(source, normalized, rule, index)
          rule.patterns.flat_map { |pattern| matches(source, normalized, rule, index, pattern) }
        rescue TIMEOUT_ERROR
          raise ArgumentError, "policy rule #{rule.name.inspect} timed out"
        end

        def matches(source, normalized, rule, index, pattern)
          scan(source, rule, index, pattern) + normalized_matches(source, normalized, rule, index, pattern)
        end

        def scan(source, rule, index, pattern)
          source.to_enum(:scan, pattern).map do
            match = Regexp.last_match
            finding(rule, index, match[0].to_s, match.begin(0), match.end(0))
          end
        end

        def normalized_matches(source, normalized, rule, index, pattern)
          return [] unless normalized.changed?

          normalized.text.to_enum(:scan, pattern).map do
            match = Regexp.last_match
            starting, ending = normalized.original_span(match.begin(0), match.end(0))
            finding(rule, index, source[starting...ending], starting, ending)
          end
        end

        def finding(rule, index, full, starting, ending)
          { rule: rule, rule_index: index, full: full, start: starting, end: ending }
        end
        private_class_method :finding, :matches, :normalized_matches, :scan
      end
    end
  end
end
