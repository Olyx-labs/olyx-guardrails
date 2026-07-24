# frozen_string_literal: true

require_relative '../text/mapped_normalization'

module Olyx
  module Guardrails
    module PolicyComponents
      # Finds normalized policy matches and maps them to original offsets.
      module NormalizedPatternMatcher
        module_function

        def call(source, rule, index, pattern)
          mapped = Text::MappedNormalization.new(source)
          return [] unless mapped.changed?

          findings(source, mapped, rule, index, pattern)
        end

        def findings(source, mapped, rule, index, pattern)
          mapped.text.to_enum(:scan, pattern).map do
            match = Regexp.last_match
            finding(source, mapped, rule, index, match)
          end
        end

        def finding(source, mapped, rule, index, match)
          starting, ending = mapped.original_span(match.begin(0), match.end(0))
          { rule: rule, rule_index: index, full: source[starting...ending], start: starting, end: ending }
        end
        private_class_method :finding, :findings
      end
    end
  end
end
