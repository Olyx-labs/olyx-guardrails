# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyComponents
      # Enumerates private offsets for one compiled policy pattern.
      module PatternMatcher
        module_function

        def call(source, rule, index, pattern)
          source.to_enum(:scan, pattern).map do
            match = Regexp.last_match
            { rule: rule, rule_index: index, full: match[0].to_s, start: match.begin(0), end: match.end(0) }
          end
        end
      end
    end
  end
end
