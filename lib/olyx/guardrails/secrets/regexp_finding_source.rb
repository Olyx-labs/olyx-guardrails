# frozen_string_literal: true

module Olyx
  module Guardrails
    module Secrets
      # Converts every Regexp match into an internal offset-aware finding.
      module RegexpFindingSource
        module_function

        def call(source, category, pattern)
          source.to_enum(:scan, pattern).map { finding(category, Regexp.last_match) }
        end

        def finding(category, match)
          { category: category, full: match[0].to_s, start: match.begin(0), end: match.end(0) }
        end
        private_class_method :finding
      end
    end
  end
end
